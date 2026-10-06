"""Phase 22: the delivery hardening is policy, and policy is tested.

Each rule here was a deliberate decision (see docs/phases/phase-22-delivery.md); a later edit that
quietly undoes one - an unpinned image, a mutable action tag, a write-all token, a container
running as root - fails the build instead of shipping.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
COMPOSE_FILES = [
    ROOT / "docker-compose.yml",
    ROOT / "deploy/observability/compose.observability.yml",
]
SHA_PIN = re.compile(r"@[0-9a-f]{40}$")
DIGEST_PIN = re.compile(r"@sha256:[0-9a-f]{64}$")


def load(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------ the image
def test_dockerfile_pins_bases_and_runs_unprivileged() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    images = re.findall(r"^ARG \w+_IMAGE=(\S+)$", dockerfile, flags=re.MULTILINE)
    assert images, "base images are declared as ARGs"
    assert all(DIGEST_PIN.search(image) for image in images), images
    stages = dockerfile.split("\nFROM ")
    runtime = stages[-1]
    assert re.search(r"^USER 10001:10001$", runtime, flags=re.MULTILINE)
    assert "--chown=root:root /app/.venv" in runtime  # the app cannot rewrite its own code
    assert "HEALTHCHECK" in runtime
    assert not re.search(r"^ADD\s+https?://", dockerfile, flags=re.MULTILINE)
    assert not re.search(r"curl[^\n|]*\|\s*(ba)?sh", dockerfile)
    for install in re.findall(r"apt-get install[^\n]*", dockerfile):
        assert "--no-install-recommends" in install


def test_build_context_is_an_allow_list() -> None:
    lines = [
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert lines[0] == "**", "everything is excluded unless allowed"
    allowed = {line[1:] for line in lines if line.startswith("!")}
    for forbidden in (".env", ".git/**", "tests/**", "var/**", ".venv/**"):
        assert forbidden not in allowed


# -------------------------------------------------------------------------------- workflows
@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_pin_actions_and_start_read_only(workflow: Path) -> None:
    text = workflow.read_text(encoding="utf-8")
    document = load(workflow)
    assert document["permissions"] == {"contents": "read"}, "default token is read-only"
    triggers = document.get(True) or document.get("on")
    assert "pull_request_target" not in (triggers or {}), "untrusted code with secrets"
    for action in re.findall(r"^\s*-?\s*uses:\s*(\S+)", text, flags=re.MULTILINE):
        if action.startswith("./"):
            continue
        assert SHA_PIN.search(action), f"{workflow.name}: {action} is not pinned to a commit"
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step.get("with", {}).get("persist-credentials") is False


def test_composite_actions_are_pinned_too() -> None:
    for action in (ROOT / ".github" / "actions").glob("*/action.yml"):
        for uses in re.findall(r"uses:\s*(\S+)", action.read_text(encoding="utf-8")):
            assert SHA_PIN.search(uses), f"{action}: {uses}"


def test_releases_run_full_ci_and_sign_by_identity() -> None:
    release = load(ROOT / ".github/workflows/release.yml")
    assert release["jobs"]["verify"]["uses"] == "./.github/workflows/ci.yml"
    image = release["jobs"]["image"]
    assert image["needs"] == ["verify"]
    assert image["environment"] == "release"
    assert image["permissions"]["id-token"] == "write"
    script = "\n".join(str(step.get("run", "")) for step in image["steps"])
    assert "cosign sign" in script
    assert "cosign verify" in script
    assert "--certificate-identity" in script
    build = next(step for step in image["steps"] if step.get("id") == "build")
    assert build["with"]["sbom"] is True
    assert build["with"]["provenance"] == "mode=max"


# ---------------------------------------------------------------------------------- compose
@pytest.mark.parametrize("compose_file", COMPOSE_FILES, ids=lambda p: p.name)
def test_compose_images_are_pinned_and_ports_local(compose_file: Path) -> None:
    services = load(compose_file)["services"]
    for name, service in services.items():
        if "image" in service and not str(service["image"]).startswith("argus:"):
            assert DIGEST_PIN.search(service["image"]), name
        for port in service.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), (name, port)


def test_application_containers_are_locked_down() -> None:
    app = load(ROOT / "docker-compose.yml")["x-app"]
    assert app["read_only"] is True
    assert app["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in app["security_opt"]


def test_ci_validates_with_the_images_the_stack_runs() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    services = load(ROOT / "deploy/observability/compose.observability.yml")["services"]
    for name in ("prometheus", "otel-collector"):
        assert services[name]["image"] in ci, f"{name}: CI checks a different version"
