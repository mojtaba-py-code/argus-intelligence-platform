"""Phase 23: the Kubernetes manifests keep their security properties.

CI renders both overlays and validates them against the Kubernetes schemas (kubeconform); these
tests check what schemas cannot: the restricted pod-security profile on every workload, the
owner credentials reaching only the operator jobs, default-deny networking that keeps cloud
metadata and private ranges unreachable from the internet rules, and pinned overlays.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
K8S = ROOT / "deploy" / "kubernetes"
BASE = K8S / "base"


def documents(path: Path) -> list[dict[str, Any]]:
    return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]


def base_objects() -> list[dict[str, Any]]:
    kustomization = documents(BASE / "kustomization.yaml")[0]
    objects: list[dict[str, Any]] = []
    for resource in kustomization["resources"]:
        assert (BASE / resource).exists(), resource
        objects.extend(documents(BASE / resource))
    return objects


def pod_spec(obj: dict[str, Any]) -> dict[str, Any] | None:
    kind = obj["kind"]
    if kind in {"Deployment", "Job"}:
        template: dict[str, Any] = obj["spec"]["template"]
    elif kind == "CronJob":
        template = obj["spec"]["jobTemplate"]["spec"]["template"]
    else:
        return None
    spec: dict[str, Any] = template["spec"]
    return spec


WORKLOADS = [obj for obj in base_objects() if pod_spec(obj) is not None]


@pytest.mark.parametrize(
    "workload", WORKLOADS, ids=lambda o: f"{o['kind']}/{o['metadata']['name']}"
)
def test_every_workload_meets_the_restricted_profile(workload: dict[str, Any]) -> None:
    spec = pod_spec(workload)
    assert spec is not None
    assert spec["automountServiceAccountToken"] is False
    pod = spec["securityContext"]
    assert pod["runAsNonRoot"] is True
    assert pod["runAsUser"] == 10001
    assert pod["seccompProfile"] == {"type": "RuntimeDefault"}
    for forbidden in ("hostNetwork", "hostPID", "hostIPC"):
        assert not spec.get(forbidden)
    assert not any("hostPath" in volume for volume in spec.get("volumes", []))
    for container in spec["containers"]:
        security = container["securityContext"]
        assert security["allowPrivilegeEscalation"] is False
        assert security["readOnlyRootFilesystem"] is True
        assert security["capabilities"] == {"drop": ["ALL"]}
        assert container["image"] == "argus", "overlays pin the image by digest"
        assert container["resources"]["requests"]
        assert container["resources"]["limits"]["memory"]


def test_only_operator_jobs_receive_the_owner_credentials() -> None:
    for workload in WORKLOADS:
        spec = pod_spec(workload)
        assert spec is not None
        secrets = {
            source["secretRef"]["name"]
            for container in spec["containers"]
            for source in container.get("envFrom", [])
            if "secretRef" in source
        }
        operator = workload["kind"] in {"Job", "CronJob"}
        assert ("argus-owner" in secrets) is operator, workload["metadata"]["name"]
        assert (spec["serviceAccountName"] == "argus-operator") is operator


def test_long_running_workloads_have_probes_and_graceful_shutdown() -> None:
    for workload in WORKLOADS:
        if workload["kind"] != "Deployment":
            continue
        spec = pod_spec(workload)
        assert spec is not None
        container = spec["containers"][0]
        assert "livenessProbe" in container, workload["metadata"]["name"]
        assert spec["terminationGracePeriodSeconds"] >= 30
    api = next(w for w in WORKLOADS if w["metadata"]["name"] == "argus-api")
    container = api["spec"]["template"]["spec"]["containers"][0]
    assert container["readinessProbe"]["httpGet"]["path"] == "/health/ready"
    assert api["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] == 0


def test_namespace_enforces_restricted_pod_security() -> None:
    namespace = next(o for o in base_objects() if o["kind"] == "Namespace")
    assert namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"


def test_network_is_default_deny_and_internet_rules_exclude_internal_ranges() -> None:
    policies = {o["metadata"]["name"]: o for o in base_objects() if o["kind"] == "NetworkPolicy"}
    deny = policies["default-deny"]["spec"]
    assert deny["podSelector"] == {}
    assert set(deny["policyTypes"]) == {"Ingress", "Egress"}
    assert "ingress" not in deny
    assert "egress" not in deny
    for name in ("egress-internet", "egress-web-http-workers"):
        for rule in policies[name]["spec"]["egress"]:
            for peer in rule["to"]:
                block = peer["ipBlock"]
                if block["cidr"] == "0.0.0.0/0":
                    assert {"169.254.0.0/16", "10.0.0.0/8", "127.0.0.0/8"} <= set(block["except"])
                else:
                    assert {"fc00::/7", "fe80::/10"} <= set(block["except"])
    scheduler_reaches_internet = any(
        "scheduler" in str(policies[name]["spec"]["podSelector"])
        for name in ("egress-internet", "egress-web-http-workers")
    )
    assert not scheduler_reaches_internet


@pytest.mark.parametrize("overlay", ["staging", "production"])
def test_overlays_pin_the_image_and_configure_https(overlay: str) -> None:
    kustomization = documents(K8S / "overlays" / overlay / "kustomization.yaml")[0]
    assert kustomization["resources"] == ["../../base"]
    image = kustomization["images"][0]
    assert image["name"] == "argus"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", image["digest"])
    assert "newTag" not in image
    config_patch = next(p for p in kustomization["patches"] if p["target"]["kind"] == "ConfigMap")
    operations = {op["path"]: op["value"] for op in yaml.safe_load(config_patch["patch"])}
    assert operations["/data/ARGUS_HTTP__PUBLIC_BASE_URL"].startswith("https://")
    assert operations["/data/ARGUS_OBSERVABILITY__OTEL_ENDPOINT"].startswith("https://")


def test_the_secret_template_holds_placeholders_only() -> None:
    for secret in documents(K8S / "secrets.example.yaml"):
        for name, value in secret["stringData"].items():
            assert "<" in value, f"{name} must stay a placeholder"
    runtime = documents(K8S / "secrets.example.yaml")[0]["stringData"]
    assert "ARGUS_DATABASE__MIGRATION_URL" not in runtime
