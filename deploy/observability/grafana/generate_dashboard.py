"""Generate ``dashboards/argus-overview.json`` - the dashboard is code, reviewed like code.

    python deploy/observability/grafana/generate_dashboard.py

``tests/unit/test_observability_assets.py`` fails when the committed JSON differs from what this
script produces, and when any query names a metric the application does not export.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DATASOURCE = {"type": "prometheus", "uid": "argus-prometheus"}
OUTPUT = Path(__file__).parent / "dashboards" / "argus-overview.json"

# (row title, [(panel title, unit, [(expr, legend)], kind)])
Query = tuple[str, str]
Panel = tuple[str, str, list[Query], str]
ROWS: list[tuple[str, list[Panel]]] = [
    (
        "API",
        [
            (
                "Requests per second by status",
                "reqps",
                [("sum by (status) (rate(argus_http_requests_total[5m]))", "{{status}}")],
                "timeseries",
            ),
            (
                "Server error ratio",
                "percentunit",
                [
                    (
                        (
                            'sum(rate(argus_http_requests_total{status=~"5.."}[5m]))'
                            " / clamp_min(sum(rate(argus_http_requests_total[5m])), 1e-9)"
                        ),
                        "5xx",
                    )
                ],
                "stat",
            ),
            (
                "p95 latency by route",
                "s",
                [
                    (
                        (
                            "histogram_quantile(0.95, sum by (le, route) "
                            "(rate(argus_http_request_duration_seconds_bucket[5m])))"
                        ),
                        "{{route}}",
                    )
                ],
                "timeseries",
            ),
            (
                "Rate-limit refusals by policy",
                "ops",
                [("sum by (policy) (rate(argus_rate_limited_total[5m]))", "{{policy}}")],
                "timeseries",
            ),
        ],
    ),
    (
        "Jobs and research",
        [
            (
                "Queue depth",
                "short",
                [("max by (queue) (argus_queue_depth)", "{{queue}}")],
                "timeseries",
            ),
            (
                "Job outcomes",
                "ops",
                [("sum by (task, outcome) (rate(argus_jobs_total[5m]))", "{{task}} {{outcome}}")],
                "timeseries",
            ),
            (
                "Job duration p95 by task",
                "s",
                [
                    (
                        (
                            "histogram_quantile(0.95, sum by (le, task) "
                            "(rate(argus_job_duration_seconds_bucket[15m])))"
                        ),
                        "{{task}}",
                    )
                ],
                "timeseries",
            ),
            (
                "Research duration (completed jobs)",
                "s",
                [
                    (
                        (
                            "histogram_quantile(0.5, sum by (le) (rate("
                            'argus_research_duration_seconds_bucket{outcome="completed"}[1h])))'
                        ),
                        "p50",
                    ),
                    (
                        (
                            "histogram_quantile(0.95, sum by (le) (rate("
                            'argus_research_duration_seconds_bucket{outcome="completed"}[1h])))'
                        ),
                        "p95",
                    ),
                ],
                "timeseries",
            ),
            (
                "Scheduler duties (last hour)",
                "short",
                [
                    (
                        "sum by (task, outcome) (increase(argus_scheduler_task_runs_total[1h]))",
                        "{{task}} {{outcome}}",
                    )
                ],
                "timeseries",
            ),
        ],
    ),
    (
        "AI",
        [
            (
                "Tokens per minute by model",
                "short",
                [
                    (
                        "sum by (model, direction) (rate(argus_llm_tokens_total[5m])) * 60",
                        "{{model}} {{direction}}",
                    )
                ],
                "timeseries",
            ),
            (
                "Cost per hour by model",
                "currencyUSD",
                [("sum by (model) (increase(argus_llm_cost_usd_total[1h]))", "{{model}}")],
                "timeseries",
            ),
            (
                "Model call outcomes",
                "ops",
                [("sum by (outcome) (rate(argus_llm_requests_total[5m]))", "{{outcome}}")],
                "timeseries",
            ),
            (
                "Model latency p95",
                "s",
                [
                    (
                        (
                            "histogram_quantile(0.95, sum by (le, model) "
                            "(rate(argus_llm_request_duration_seconds_bucket[5m])))"
                        ),
                        "{{model}}",
                    )
                ],
                "timeseries",
            ),
            (
                "Agent runs by termination (last hour)",
                "short",
                [
                    (
                        "sum by (agent, termination) (increase(argus_agent_runs_total[1h]))",
                        "{{agent}} {{termination}}",
                    )
                ],
                "timeseries",
            ),
            (
                "Agent tool calls by outcome (last hour)",
                "short",
                [
                    (
                        "sum by (tool, outcome) (increase(argus_agent_tool_calls_total[1h]))",
                        "{{tool}} {{outcome}}",
                    )
                ],
                "timeseries",
            ),
        ],
    ),
    (
        "Knowledge",
        [
            (
                "Retrieval cache hit ratio",
                "percentunit",
                [
                    (
                        (
                            'sum(rate(argus_knowledge_retrievals_total{cache="hit"}[15m]))'
                            " / clamp_min(sum(rate(argus_knowledge_retrievals_total[15m])), 1e-9)"
                        ),
                        "hit ratio",
                    )
                ],
                "stat",
            ),
            (
                "Searches that found nothing",
                "percentunit",
                [
                    (
                        (
                            'sum(rate(argus_knowledge_retrieval_results_bucket{le="0.0"}[1h]))'
                            " / clamp_min(sum(rate(argus_knowledge_retrieval_results_count[1h])), 1e-9)"
                        ),
                        "empty",
                    )
                ],
                "stat",
            ),
            (
                "Retrieval latency p95",
                "s",
                [
                    (
                        (
                            "histogram_quantile(0.95, sum by (le) "
                            "(rate(argus_retrieval_duration_seconds_bucket[5m])))"
                        ),
                        "p95",
                    )
                ],
                "timeseries",
            ),
            (
                "Chunks indexed",
                "ops",
                [
                    (
                        "sum by (origin, embedded) (rate(argus_knowledge_chunks_indexed_total[15m]))",
                        "{{origin}} embedded={{embedded}}",
                    )
                ],
                "timeseries",
            ),
            (
                "Documents (last hour)",
                "short",
                [("sum by (event) (increase(argus_documents_total[1h]))", "{{event}}")],
                "timeseries",
            ),
        ],
    ),
    (
        "Web and security",
        [
            (
                "Fetch outcomes",
                "ops",
                [("sum by (outcome) (rate(argus_fetches_total[5m]))", "{{outcome}}")],
                "timeseries",
            ),
            (
                "Egress blocked by reason (last hour)",
                "short",
                [("sum by (reason) (increase(argus_egress_blocked_total[1h]))", "{{reason}}")],
                "timeseries",
            ),
            (
                "Prompt-injection detections (last hour)",
                "short",
                [("sum by (level) (increase(argus_injection_detections_total[1h]))", "{{level}}")],
                "timeseries",
            ),
            (
                "Denied member actions (last hour)",
                "short",
                [
                    (
                        "sum by (recorded) (increase(argus_access_denied_total[1h]))",
                        "recorded={{recorded}}",
                    )
                ],
                "timeseries",
            ),
            (
                "Audit verifications (last 6 hours)",
                "short",
                [("sum by (result) (increase(argus_audit_verifications_total[6h]))", "{{result}}")],
                "stat",
            ),
            (
                "Rate limits degraded (last hour)",
                "short",
                [("sum(increase(argus_ratelimit_degraded_total[1h]))", "degraded")],
                "stat",
            ),
        ],
    ),
    (
        "Database",
        [
            (
                "Statement latency p95 by operation",
                "s",
                [
                    (
                        (
                            "histogram_quantile(0.95, sum by (le, operation) "
                            "(rate(argus_db_query_duration_seconds_bucket[5m])))"
                        ),
                        "{{operation}}",
                    )
                ],
                "timeseries",
            ),
            (
                "Connection pool usage",
                "short",
                [
                    (
                        "sum by (state) (argus_db_pool_connections)",
                        "{{state}}",
                    ),
                    ("sum(argus_db_pool_capacity)", "capacity"),
                ],
                "timeseries",
            ),
            (
                "Statements per second by operation",
                "ops",
                [
                    (
                        "sum by (operation) (rate(argus_db_query_duration_seconds_count[5m]))",
                        "{{operation}}",
                    )
                ],
                "timeseries",
            ),
        ],
    ),
]


def build() -> dict[str, Any]:
    panels: list[dict[str, Any]] = []
    panel_id = 1
    y = 0
    for row_title, row_panels in ROWS:
        panels.append(
            {
                "id": panel_id,
                "type": "row",
                "title": row_title,
                "collapsed": False,
                "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
                "panels": [],
            }
        )
        panel_id += 1
        y += 1
        for index, (title, unit, queries, kind) in enumerate(row_panels):
            width = 6 if kind == "stat" else 12
            x = (index % 2) * 12
            panels.append(
                {
                    "id": panel_id,
                    "type": kind,
                    "title": title,
                    "datasource": DATASOURCE,
                    "gridPos": {"h": 8, "w": width, "x": x, "y": y + (index // 2) * 8},
                    "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
                    "options": {"legend": {"displayMode": "list", "placement": "bottom"}}
                    if kind == "timeseries"
                    else {"reduceOptions": {"calcs": ["lastNotNull"]}},
                    "targets": [
                        {
                            "refId": chr(ord("A") + number),
                            "datasource": DATASOURCE,
                            "expr": expr,
                            "legendFormat": legend,
                        }
                        for number, (expr, legend) in enumerate(queries)
                    ],
                }
            )
            panel_id += 1
        y += ((len(row_panels) + 1) // 2) * 8
    return {
        "uid": "argus-overview",
        "title": "Argus - Overview",
        "tags": ["argus"],
        "timezone": "utc",
        "schemaVersion": 39,
        "version": 1,
        "editable": False,
        "refresh": "30s",
        "time": {"from": "now-6h", "to": "now"},
        "templating": {"list": []},
        "annotations": {"list": []},
        "links": [],
        "panels": panels,
    }


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    OUTPUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUTPUT}")  # noqa: T201 - command-line script
