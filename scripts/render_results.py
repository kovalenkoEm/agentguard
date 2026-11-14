#!/usr/bin/env python3
"""Render eval results as the markdown tables used in README.md.

    python scripts/render_results.py benchmarks/results/qwen2.5-3b.json
    python scripts/render_results.py benchmarks/results/*.json --combined

Keeping the README tables generated (rather than hand-typed) means a stale claim
is a visible diff, not a silent one.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pct(hit: int, total: int) -> str:
    return f"{hit}/{total} ({100 * hit / total:.0f}%)" if total else "-"


def table(rows: list[tuple[str, int, str, str, int]], title: str) -> str:
    out = [
        f"| {title} | cases | baseline | agentguard | blocked calls |",
        "|---|---:|---|---|---:|",
    ]
    total = [0, 0, 0, 0]
    for family, cases, base, guard, blocked in rows:
        out.append(f"| {family} | {cases} | {base} | {guard} | {blocked} |")
    return "\n".join(out)


def one(data: dict) -> str:
    rows = []
    b_hit = b_tot = g_hit = g_tot = blocked_all = 0
    for family, stats in data["by_family"].items():
        if family == "benign":
            continue
        cases = len(stats.get("ids", []))
        rows.append(
            (
                family,
                cases,
                pct(*stats["baseline"]),
                pct(*stats["guard"]),
                stats["blocked"],
            )
        )
        b_hit += stats["baseline"][0]
        b_tot += stats["baseline"][1]
        g_hit += stats["guard"][0]
        g_tot += stats["guard"][1]
        blocked_all += stats["blocked"]
    rows.append(("**all attacks**", b_tot, f"**{pct(b_hit, b_tot)}**", f"**{pct(g_hit, g_tot)}**", blocked_all))
    body = table(rows, "family")
    util = data.get("utility") or {}
    if util.get("baseline"):
        body += (
            f"\n\nUtility on benign tasks: baseline {pct(*util['baseline'].values())}, "
            f"agentguard {pct(*util['agentguard'].values())}"
        )
    return body


def combined(datasets: list[dict]) -> str:
    lines = ["| family | cases | " + " | ".join(d["model"] for d in datasets) + " |", "|---|---:|" + "---|" * len(datasets)]
    families = [f for f in datasets[0]["by_family"] if f != "benign"]
    for family in families:
        cells = []
        for d in datasets:
            stats = d["by_family"].get(family)
            cells.append(pct(*stats["baseline"]) if stats else "-")
        cases = len(datasets[0]["by_family"][family].get("ids", []))
        lines.append(f"| {family} | {cases} | " + " | ".join(cells) + " |")
    lines.append(
        "| **all attacks** | "
        + str(datasets[0]["asr"]["baseline"]["total"])
        + " | "
        + " | ".join(f"**{pct(d['asr']['baseline']['hit'], d['asr']['baseline']['total'])}**" for d in datasets)
        + " |"
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", nargs="+", type=Path)
    parser.add_argument("--combined", action="store_true", help="one column per results file")
    args = parser.parse_args()

    datasets = [load(p) for p in args.results]
    if args.combined:
        print(combined(datasets))
        return 0
    for data in datasets:
        print(f"\n### {data['model']} ({data['mode']}, split={data['split']})\n")
        print(one(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
