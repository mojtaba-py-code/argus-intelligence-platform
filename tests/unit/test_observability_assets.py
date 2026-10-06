"""The observability configuration must match the code it observes.

An alert on a metric that no longer exists never fires; a dashboard panel on one stays empty -
both fail silently. These tests make them fail loudly instead.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from prometheus_client.core import Metric

from argus.infrastructure.observability.metrics import Metrics

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy" / "observability"
ALERTS = DEPLOY / "prometheus" / "rules" / "argus-alerts.yml"
DASHBOARD = DEPLOY / "grafana" / "dashboards" / "argus-overview.json"
RUNBOOKS = ROOT / "docs" / "operations" / "alerts.md"
METRIC_NAME = re.compile(r"\bargus_[a-z0-9_]+")
SUFFIXES = {
    "counter": ("_total",),
    "histogram": ("_bucket", "_count", "_sum"),
    "gauge": ("",),
}


def exported_series() -> set[str]:
    names: set[str] = set()
    family: Metric
    for family in Metrics().registry.collect():
        for suffix in SUFFIXES.get(family.type, ("",)):
            names.add(family.name + suffix)
    return names


def alert_rules() -> list[dict[str, Any]]:
    document = yaml.safe_load(ALERTS.read_text(encoding="utf-8"))
    return [rule for group in document["groups"] for rule in group["rules"]]


def dashboard_queries() -> list[str]:
    dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    return [target["expr"] for panel in dashboard["panels"] for target in panel.get("targets", [])]


def anchors(markdown: str) -> set[str]:
    return {
        re.sub(r"[^a-z0-9-]", "", heading.strip().lower().replace(" ", "-"))
        for heading in re.findall(r"^#{2,4} (.+)$", markdown, flags=re.MULTILINE)
    }


def test_every_alert_is_complete_and_documented() -> None:
    rules = alert_rules()
    assert len(rules) >= 15
    names = [rule["alert"] for rule in rules]
    assert len(names) == len(set(names)), "alert names must be unique"
    documented = anchors(RUNBOOKS.read_text(encoding="utf-8"))
    for rule in rules:
        assert rule["labels"]["severity"] in {"critical", "warning"}, rule["alert"]
        annotations = rule["annotations"]
        assert annotations["summary"], rule["alert"]
        assert annotations["description"], rule["alert"]
        page, _, anchor = annotations["runbook_url"].partition("#")
        assert page == "docs/operations/alerts.md", rule["alert"]
        assert anchor == rule["alert"].lower(), rule["alert"]
        assert anchor in documented, f"runbook section missing for {rule['alert']}"


@pytest.mark.parametrize("source", ["alerts", "dashboard"])
def test_queries_only_use_metrics_the_code_exports(source: str) -> None:
    expressions = (
        [rule["expr"] for rule in alert_rules()] if source == "alerts" else dashboard_queries()
    )
    exported = exported_series()
    used = {name for expr in expressions for name in METRIC_NAME.findall(expr)}
    assert used, "no metrics found - the pattern needs updating"
    unknown = sorted(used - exported)
    assert not unknown, f"{source} reference metrics the code does not export: {unknown}"


def test_histogram_bucket_selectors_match_real_bucket_bounds() -> None:
    """``le`` values are rendered as floats ("0.0", not "0"): a wrong string never matches."""
    expressions = [rule["expr"] for rule in alert_rules()] + dashboard_queries()
    for bound in re.findall(r'le="([^"]+)"', " ".join(expressions)):
        assert bound == "+Inf" or "." in bound, bound


def test_the_committed_dashboard_is_what_the_generator_produces() -> None:
    spec = importlib.util.spec_from_file_location(
        "generate_dashboard", DEPLOY / "grafana" / "generate_dashboard.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert DASHBOARD.read_text(encoding="utf-8") == module.render(), (
        "run: python deploy/observability/grafana/generate_dashboard.py"
    )


def test_collector_scrubs_sensitive_attributes_on_the_only_pipeline() -> None:
    config = yaml.safe_load((DEPLOY / "otel-collector.yaml").read_text(encoding="utf-8"))
    pipeline = config["service"]["pipelines"]["traces"]
    assert pipeline["processors"][0] == "memory_limiter"
    assert "attributes/scrub" in pipeline["processors"]
    deleted = {
        action["key"]
        for action in config["processors"]["attributes/scrub"]["actions"]
        if action["action"] == "delete"
    }
    assert {"url.full", "url.query", "http.request.header.authorization", "user.email"} <= deleted
    for component in pipeline["receivers"] + pipeline["processors"] + pipeline["exporters"]:
        section = (
            "receivers"
            if component in pipeline["receivers"]
            else "processors"
            if component in pipeline["processors"]
            else "exporters"
        )
        assert component in config[section], component


def test_local_stack_binds_ui_ports_to_localhost_and_pins_images() -> None:
    compose = yaml.safe_load((DEPLOY / "compose.observability.yml").read_text(encoding="utf-8"))
    for name, service in compose["services"].items():
        for port in service.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), (name, port)
        if "image" in service:
            assert "@sha256:" in service["image"], name
    prometheus = yaml.safe_load(
        (DEPLOY / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")
    )
    jobs = {job["job_name"] for job in prometheus["scrape_configs"]}
    assert jobs == {"argus-api", "argus-worker", "argus-scheduler"}
