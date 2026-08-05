"""Suite / category catalog for Primitive Bench reports.

Keeps case-folder ranges and HTML sidebar labels in one place so
`agent_cases` and `agent_cases_feedback` (and future folders) do not
hard-code suite keys inside the runner/HTML renderer.
"""

from __future__ import annotations

import re
from pathlib import Path

# Display labels for the HTML sidebar / console summary.
SUITE_LABELS: dict[str, str] = {
    "original": "Original (001–030)",
    "extra": "Extra (031–130)",
    "open_probe": "Open probes",
    "fb_weak_binding": "Feedback · Weak / Binding (001–007)",
    "fb_strong_baseline": "Feedback · Strong Baselines (008–012)",
    "fb_entity_bind": "Feedback · Entity / Temporal Bind (013–032)",
    "fb_multihop": "Feedback · Multi-hop / Aggregate (033–052)",
    "fb_policy": "Feedback · Policy / Abstain / Verify (053–072)",
    "fb_ops": "Feedback · Ops / Formats (073–092)",
    "fb_encoding": "Feedback · Encoding / Web / Math (093–112)",
    "other": "Other",
}

# Preferred sidebar / summary order. Suites with zero tasks are skipped at render time.
SUITE_ORDER: list[str] = [
    "original",
    "extra",
    "open_probe",
    "fb_weak_binding",
    "fb_strong_baseline",
    "fb_entity_bind",
    "fb_multihop",
    "fb_policy",
    "fb_ops",
    "fb_encoding",
    "other",
]

# Inclusive case_id ranges keyed by the cases folder basename.
FOLDER_RANGES: dict[str, list[tuple[int, int, str]]] = {
    "agent_cases": [
        (1, 30, "original"),
        (31, 130, "extra"),
    ],
    "agent_cases_feedback": [
        (1, 7, "fb_weak_binding"),
        (8, 12, "fb_strong_baseline"),
        (13, 32, "fb_entity_bind"),
        (33, 52, "fb_multihop"),
        (53, 72, "fb_policy"),
        (73, 92, "fb_ops"),
        (93, 112, "fb_encoding"),
    ],
}


def cases_folder_key(cases_dir: str | Path) -> str:
    """Basename used to look up FOLDER_RANGES (e.g. agent_cases_feedback)."""
    return Path(cases_dir).name


def case_id_from_path(path: Path) -> int | None:
    match = re.match(r"^(\d+)_", path.name)
    return int(match.group(1)) if match else None


def resolve_suite(
    case_id: int | None,
    mode: str = "benchmark",
    cases_dir: str | Path = "agent_cases",
    explicit: str | None = None,
) -> str:
    """Resolve a suite key from optional JSON override, then folder ranges."""
    if mode == "open_probe":
        return "open_probe"
    if isinstance(explicit, str) and explicit in SUITE_LABELS:
        return explicit
    folder = cases_folder_key(cases_dir)
    ranges = FOLDER_RANGES.get(folder)
    if case_id is not None and ranges:
        for lo, hi, key in ranges:
            if lo <= case_id <= hi:
                return key
    return "other"


def suite_label(suite_key: str) -> str:
    return SUITE_LABELS.get(suite_key, suite_key)


def iter_suite_keys_for(results_suites: set[str]) -> list[str]:
    """Stable order: known catalog keys first, then any unexpected keys."""
    ordered = [key for key in SUITE_ORDER if key in results_suites]
    extras = sorted(key for key in results_suites if key not in SUITE_ORDER)
    return ordered + extras
