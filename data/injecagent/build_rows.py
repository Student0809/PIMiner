"""Build PIMiner injection-step rows from the PISmith InjecAgent dataset.

Faithful port: each PISmith InjecAgent record (train.json + test.json) becomes one
PIMiner row. The injection slot is the `<Attacker Instruction>` placeholder inside
the tool's returned observation (`Tool Response Template`) — exactly where PISmith
substitutes the attacker's crafted prompt. PIMiner's attacker writes an <injection>
that the injecagent reward substitutes for `<Attacker Instruction>` at eval time.

InjecAgent is a single-completion, tool-calling benchmark: the user tool has already
been "called" and its observation (carrying the injection) is shown to the agent;
attack success = the agent next calls the attacker tool (`Attacker Tools[0]`).

Run:  python data/injecagent/build_rows.py
Writes data/injecagent/injecagent_rows.jsonl
"""

import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SPLITS = ["train", "test"]  # combined into one PIMiner pool; split recorded under _injecagent
PLACEHOLDER = "<Attacker Instruction>"  # PISmith's literal slot token inside Tool Response Template


def _hash(*parts: str) -> str:
    h = hashlib.md5("\x1f".join(parts).encode("utf-8")).hexdigest()
    return h[:8]


def _suite_of(attack_type: str) -> str:
    # InjecAgent's two primary classes: Direct Harm (Physical/Financial) vs Data Stealing
    # (Data Security Harm). Used as PIMiner suite_name so suite-filtering + holdout work.
    return "ds" if "data security" in (attack_type or "").lower() else "dh"


def _row_from_record(rec: dict, split: str) -> dict:
    user_instruction = rec["User Instruction"]
    user_tool = rec["User Tool"]
    attacker_tools = rec["Attacker Tools"]
    attacker_instruction = rec["Attacker Instruction"]
    attack_type = rec.get("Attack Type", "")
    template = rec["Tool Response Template"]
    suite = _suite_of(attack_type)

    # Stable, content-addressed ids so the (suite, user_task, injection_task, step)
    # holdout key is deterministic across runs.
    user_task_id = f"{user_tool}-{_hash(user_instruction)}"
    injection_task_id = f"{attacker_tools[0]}-{_hash(attacker_instruction, attacker_tools[0])}"

    return {
        "suite_name": suite,
        "user_task_id": user_task_id,
        "injection_task_id": injection_task_id,
        "step_index": 0,
        "visible_vectors": ["fill"],
        "user_task_prompt": user_instruction,
        "injection_task_goal": attacker_instruction,
        # Informational view of the injection slot for the attacker: the tool
        # observation the agent receives, with the <Attacker Instruction> slot shown.
        "context_with_placeholder": template,
        "injection_descriptions": (
            f"Injected into the observation returned by the user tool "
            f"`{user_tool}` (replaces the `{PLACEHOLDER}` slot). Attack succeeds if "
            f"the agent next calls the attacker tool `{attacker_tools[0]}`."
        ),
        # Benchmark-specific side channel consumed by InjecAgentAttackReward.evaluate().
        "_injecagent": {
            "User Instruction": user_instruction,
            "User Tool": user_tool,
            "Tool Parameters": rec["Tool Parameters"],
            "Tool Response Template": template,
            "Attacker Tools": attacker_tools,
            "Attack Type": attack_type,
            "Modifed": rec.get("Modifed"),
            "Thought": rec.get("Thought", ""),
            "Expected Achievements": rec.get("Expected Achievements", ""),
            "split": split,
        },
    }


def main() -> None:
    out_path = os.path.join(HERE, "injecagent_rows.jsonl")
    seen = set()
    rows = []
    for split in SPLITS:
        src = os.path.join(HERE, "dataset", f"{split}.json")
        with open(src) as f:
            records = json.load(f)
        for rec in records:
            row = _row_from_record(rec, split)
            key = (row["suite_name"], row["user_task_id"], row["injection_task_id"], row["step_index"])
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
    with open(out_path, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    by_suite = {}
    by_split = {}
    for r in rows:
        by_suite[r["suite_name"]] = by_suite.get(r["suite_name"], 0) + 1
        by_split[r["_injecagent"]["split"]] = by_split.get(r["_injecagent"]["split"], 0) + 1
    print(f"wrote {len(rows)} rows -> {out_path}")
    print(f"  by suite: {by_suite}")
    print(f"  by split: {by_split}")


if __name__ == "__main__":
    main()
