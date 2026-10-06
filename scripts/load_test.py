"""Read-only load test against a deployed Argus environment (staging, never production users).

    python scripts/load_test.py --base-url https://staging.example.com \
        --org <org id> --project <project id> --concurrency 20 --duration 60

The API key is read from the ``ARGUS_LOAD_TEST_KEY`` environment variable (never a command-line
argument: those end up in shell history and process listings). Create a dedicated key with
read scopes only (``org:read projects:read research:read sources:read documents:read
monitors:read``); the script sends GET requests exclusively, so it cannot change data.

Every key is rate limited (``api.principal``, 600 requests per minute): beyond that the
platform answers 429, which this script counts separately - it is the limiter working, not an
error. To measure capacity above one key's limit, run several instances with different keys.

The output gives, per endpoint, the request count, status classes and latency percentiles, and
exits non-zero when the server-error rate exceeds ``--max-error-rate``.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import sys
import time
from collections import Counter, defaultdict
from urllib.parse import urlsplit

import httpx

READ_PATHS = (
    "/api/v1/orgs/{org}",
    "/api/v1/orgs/{org}/projects",
    "/api/v1/orgs/{org}/projects/{project}",
    "/api/v1/orgs/{org}/projects/{project}/research-jobs",
    "/api/v1/orgs/{org}/projects/{project}/sources",
    "/api/v1/orgs/{org}/projects/{project}/documents",
    "/api/v1/orgs/{org}/projects/{project}/monitors",
)


def percentile(values: list[float], share: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, round(share * len(ordered)) - 1)] if ordered else 0.0


async def worker(
    client: httpx.AsyncClient,
    paths: list[str],
    deadline: float,
    latencies: dict[str, list[float]],
    statuses: dict[str, Counter[str]],
    offset: int,
) -> None:
    index = offset
    while time.monotonic() < deadline:
        path = paths[index % len(paths)]
        index += 1
        started = time.perf_counter()
        try:
            response = await client.get(path)
            kind = "429" if response.status_code == 429 else f"{response.status_code // 100}xx"
        except httpx.HTTPError as exc:
            kind = type(exc).__name__
        latencies[path].append(time.perf_counter() - started)
        statuses[path][kind] += 1


async def run(args: argparse.Namespace, key: str) -> int:
    paths = [p.format(org=args.org, project=args.project) for p in READ_PATHS]
    latencies: dict[str, list[float]] = defaultdict(list)
    statuses: dict[str, Counter[str]] = defaultdict(Counter)
    limits = httpx.Limits(
        max_connections=args.concurrency, max_keepalive_connections=args.concurrency
    )
    async with httpx.AsyncClient(
        base_url=args.base_url,
        headers={"Authorization": f"Bearer {key}", "User-Agent": "argus-load-test/1"},
        timeout=httpx.Timeout(30.0),
        limits=limits,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        deadline = time.monotonic() + args.duration
        await asyncio.gather(
            *(
                worker(client, paths, deadline, latencies, statuses, n)
                for n in range(args.concurrency)
            )
        )
    total = sum(sum(c.values()) for c in statuses.values())
    errors = sum(c["5xx"] for c in statuses.values()) + sum(
        n for c in statuses.values() for k, n in c.items() if not k[0].isdigit()
    )
    out = sys.stdout
    out.write(f"{total} requests in {args.duration}s ({total / args.duration:.1f}/s)\n\n")
    out.write(
        "| endpoint | requests | statuses | p50 ms | p95 ms | p99 ms |\n|---|---|---|---|---|---|\n"
    )
    for path in paths:
        values = latencies[path]
        if not values:
            continue
        shown = path.replace(args.org, "{org}").replace(args.project, "{project}")
        out.write(
            f"| {shown} | {len(values)} | {dict(statuses[path])} | "
            f"{statistics.median(values) * 1000:.0f} | {percentile(values, 0.95) * 1000:.0f} | "
            f"{percentile(values, 0.99) * 1000:.0f} |\n"
        )
    rate = errors / total if total else 1.0
    out.write(f"\nserver errors and failed connections: {errors} ({rate:.2%})\n")
    return 1 if rate > args.max_error_rate else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--org", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--duration", type=int, default=60, help="seconds")
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--allow-http", action="store_true", help="local testing only")
    args = parser.parse_args()
    key = os.environ.get("ARGUS_LOAD_TEST_KEY", "")
    if not key:
        parser.error("set ARGUS_LOAD_TEST_KEY to a read-only API key")
    if urlsplit(args.base_url).scheme != "https" and not args.allow_http:
        parser.error("refusing to send an API key over plain HTTP (use --allow-http locally)")
    if not 1 <= args.concurrency <= 500 or not 1 <= args.duration <= 3600:
        parser.error("concurrency must be 1-500 and duration 1-3600 seconds")
    return asyncio.run(run(args, key))


if __name__ == "__main__":
    raise SystemExit(main())
