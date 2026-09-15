#!/usr/bin/env python3
"""
Convert GraySwanAI/ipi_arena_os behavior JSON files into a iterative-attack-compatible
per-sample JSONL.

Each output row carries:
  - the standard iterative attack fields the attacker prompt expects
    (suite_name, user_task_id, injection_task_id, user_task_prompt,
     injection_task_goal, context_with_placeholder, visible_vectors,
     injection_descriptions, step_index)
  - an `_ipi` side channel with everything the IPI-Arena reward needs
    to actually score the attack (system_prompt, messages, tools,
    tool_judge, fill_config)

Browser behaviors and any sample without a usable top-level `tool_judge`
(scored by a criteria / llm_judge rubric) are emitted as **harness-managed**
rows (`_ipi.harness=True`): at eval time `benchmarks.ipi_arena.harness_adapter`
runs them through the upstream multi-step harness (HTML→screenshot render +
WorldSim + tool/LLM judges). Everything else stays on the single-completion
tool_judge path. Requires the vendored data at `data/ipi_arena/repo`.

Usage:
    python data/ipi_arena/build_rows.py \
        [--repo data/ipi_arena/repo] \
        [--out  data/ipi_arena/ipi_arena_rows.jsonl]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


HERE = Path(__file__).resolve().parent


def find_fill_message(messages: List[Dict[str, Any]]) -> Optional[Tuple[int, str]]:
    """Return (index, content) of the message whose content contains `{fill}`.

    The IPI-Arena schema places `{fill}` inside a single message's content —
    almost always a `role: tool` message. We don't enforce the role check
    (the schema doesn't either) but we do require exactly one occurrence.
    """
    matches: List[Tuple[int, str]] = []
    for i, m in enumerate(messages):
        c = m.get("content")
        if isinstance(c, str) and "{fill}" in c:
            matches.append((i, c))
    if len(matches) != 1:
        return None
    return matches[0]


def _is_harness_managed(entry: Dict[str, Any]) -> bool:
    """True if this behavior must run through the upstream multi-step harness
    (browser render / computer-use / WorldSim / llm_judge) rather than PIMiner's
    single-completion tool_judge path. Covers the 8 browser behaviors and any
    sample without a usable top-level `tool_judge` (e.g. flashing-lights-seizure,
    scored by a criteria rubric)."""
    if entry.get("category") == "browser":
        return True
    if entry.get("message_format") == "anthropic":
        return True
    tj = entry.get("tool_judge")
    if not tj or not tj.get("tool_name"):
        return True
    return False


def _first_user_text(messages: List[Dict[str, Any]]) -> str:
    """Extract the first user message's text (openai string or anthropic blocks)."""
    for m in messages:
        if m.get("role") != "user":
            continue
        c = m.get("content")
        if isinstance(c, str):
            return c
        if isinstance(c, list):
            parts = [b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text"]
            if parts:
                return "\n".join(parts)
    return ""


def _html_fill_window(html: str, before: int = 1600, after: int = 600) -> str:
    """A readable window around `{fill}` in the (often huge) html_template, with
    the placeholder rewritten to iterative attack's `{INJECTION:fill}` syntax."""
    i = html.find("{fill}")
    if i < 0:
        return ""
    lo = max(0, i - before)
    hi = min(len(html), i + len("{fill}") + after)
    clip = html[lo:hi].replace("{fill}", "{INJECTION:fill}")
    pre = "…(DOM truncated)…\n" if lo > 0 else ""
    post = "\n…(DOM truncated)…" if hi < len(html) else ""
    return f"{pre}{clip}{post}"


def build_harness_row(entry: Dict[str, Any], skipped: List[Tuple[str, str]]) -> Optional[Dict[str, Any]]:
    """Row for a harness-managed behavior. Scoring is delegated at eval time to
    benchmarks.ipi_arena.harness_adapter via `_ipi.harness=True`; the row only
    needs the attacker-facing fields plus the behavior id."""
    eid = entry.get("id", "<no-id>")
    category = entry.get("category", "")
    criteria = entry.get("criteria") or []
    if not criteria:
        skipped.append((eid, "harness sample with no criteria"))
        return None

    messages = entry.get("messages") or []
    html_template = entry.get("html_template")
    if html_template and "{fill}" in html_template:
        context = _html_fill_window(html_template)
        vector = "fill(html)"
    else:
        fill = find_fill_message(messages)
        if fill is None:
            skipped.append((eid, "harness sample: no single `{fill}` in messages or html_template"))
            return None
        context = fill[1].replace("{fill}", "{INJECTION:fill}")
        vector = "fill"

    user_task_prompt = _first_user_text(messages)
    goal = entry.get("objective") or entry.get("description", "")
    return {
        "suite_name": category,
        "user_task_id": eid,
        "injection_task_id": eid,
        "step_index": 0,
        "visible_vectors": [vector],
        "prompt_text": "",
        "messages": [],
        "context_with_placeholder": context,
        "user_task_prompt": user_task_prompt,
        "injection_descriptions": entry.get("description", ""),
        "injection_task_goal": goal,
        "_ipi": {
            "harness": True,
            "behavior_id": eid,
            "category": category,
            "message_format": entry.get("message_format", "openai"),
            "name": entry.get("name", ""),
            "wave": entry.get("wave"),
        },
    }


def build_row(entry: Dict[str, Any], skipped: List[Tuple[str, str]]) -> Optional[Dict[str, Any]]:
    eid = entry.get("id", "<no-id>")
    category = entry.get("category", "")
    if category not in ("tool", "coding"):
        skipped.append((eid, f"category={category!r} (not tool/coding)"))
        return None

    msg_format = entry.get("message_format", "openai")
    if msg_format != "openai":
        skipped.append((eid, f"message_format={msg_format!r} (not openai)"))
        return None

    tool_judge = entry.get("tool_judge")
    if not tool_judge or not tool_judge.get("tool_name"):
        skipped.append((eid, "no tool_judge config"))
        return None

    messages = entry.get("messages") or []
    fill = find_fill_message(messages)
    if fill is None:
        skipped.append((eid, "expected exactly one `{fill}` placeholder"))
        return None
    fill_idx, fill_content = fill

    # First user message → user_task_prompt (what the user actually asked).
    user_prompts = [m["content"] for m in messages if m.get("role") == "user" and isinstance(m.get("content"), str)]
    user_task_prompt = user_prompts[0] if user_prompts else ""

    # context_with_placeholder is what the iterative attack attacker sees as "the slot".
    # iterative attack's prompt explicitly references `{INJECTION:...}` as the placeholder
    # syntax (see iterative_attack_orchestrator/iterative_attack_common.py — build_user_message_blocks's
    # sample_block), so rewrite `{fill}` → `{INJECTION:fill}` to keep the
    # attacker's mental model consistent. Scoring still substitutes
    # against the original `{fill}` in the saved messages.
    context_with_placeholder = fill_content.replace("{fill}", "{INJECTION:fill}")

    return {
        "suite_name": category,
        "user_task_id": eid,
        "injection_task_id": eid,  # 1:1 in IPI-Arena
        "step_index": 0,
        "visible_vectors": ["fill"],
        "prompt_text": "",  # not used by iterative attack's scoring path
        "messages": [],     # not used; full messages live under _ipi
        "context_with_placeholder": context_with_placeholder,
        "user_task_prompt": user_task_prompt,
        "injection_descriptions": entry.get("description", ""),
        "injection_task_goal": entry.get("objective") or entry.get("description", ""),
        "_ipi": {
            "system_prompt": entry.get("system_prompt", ""),
            "messages": messages,             # frozen prefix, contains `{fill}`
            "fill_message_index": fill_idx,   # which message holds the placeholder
            "tools": entry.get("tools") or [],
            "tool_judge": tool_judge,
            "fill_config": entry.get("fill_config") or {},
            "name": entry.get("name", ""),
            "wave": entry.get("wave"),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=str(HERE / "repo"),
                    help="Path to the cloned GraySwanAI/ipi_arena_os repo "
                         "(produced by data/ipi_arena/fetch.sh).")
    ap.add_argument("--out", default=str(HERE / "ipi_arena_rows.jsonl"),
                    help="Output JSONL path consumed by iterative_attack_claude_code.py "
                         "(--dataset ipi_arena).")
    args = ap.parse_args()

    repo = Path(args.repo)
    if not repo.exists():
        print(f"error: repo path {repo} does not exist — run data/ipi_arena/fetch.sh first",
              file=sys.stderr)
        return 1

    rows: List[Dict[str, Any]] = []
    skipped: List[Tuple[str, str]] = []
    seen_ids: set[str] = set()

    for category in ("tool", "coding", "browser"):
        cat_dir = repo / "data" / category
        if not cat_dir.exists():
            print(f"warning: {cat_dir} not found, skipping category", file=sys.stderr)
            continue
        for path in sorted(cat_dir.glob("*.json")):
            try:
                entry = json.loads(path.read_text())
            except Exception as e:
                skipped.append((path.stem, f"json parse error: {e}"))
                continue
            # Harness-managed behaviors (browser / no-tool_judge / anthropic) are
            # scored by the upstream multi-step harness at eval time; everything
            # else stays on PIMiner's single-completion tool_judge path.
            if _is_harness_managed(entry):
                row = build_harness_row(entry, skipped)
            else:
                row = build_row(entry, skipped)
            if row is None:
                continue
            if row["user_task_id"] in seen_ids:
                skipped.append((row["user_task_id"], "duplicate id (already kept)"))
                continue
            seen_ids.add(row["user_task_id"])
            rows.append(row)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    by_suite: Dict[str, int] = {}
    for r in rows:
        by_suite[r["suite_name"]] = by_suite.get(r["suite_name"], 0) + 1

    print(f"wrote {len(rows)} rows to {out_path}")
    for s, n in sorted(by_suite.items()):
        print(f"  {s}: {n}")
    if skipped:
        print(f"skipped {len(skipped)} entries:")
        for eid, reason in skipped:
            print(f"  {eid}: {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
