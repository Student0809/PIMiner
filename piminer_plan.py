#!/usr/bin/env python3
"""piminer_plan.py — expand ONE experiment spec into the train + test plan files.

You hand-edit a single YAML spec that lists the training sequence and the test
sequence in minimal form (dataset, target, n). This builder derives every fiddly
field the parallel drivers need — `sample_offset`, `run_dir`, `k`, `status` — and
writes:

    eval_results/pim_train/<name>/train_plan.json   (consumed by piminer_train_parallel.sh)
    eval_results/pim_test/<name>/test_plan.json      (consumed by piminer_test_parallel.sh)

Sample offsets are keyed by BENCHMARK ONLY, not by target. The training set for
a benchmark is shared across every target LLM (you attack the SAME samples against
gpt-5-nano, gpt-5, haiku, ... — that is the point of training across models), so:
  * every train entry on a benchmark uses offset 0 (the same window);
  * every test  entry on a benchmark uses offset = max(train n on that benchmark),
    so the (shared) test window sits right after the (shared) train window.
Train and test therefore never reuse a sample, while different targets on the same
benchmark DO reuse the same samples. Disjointness is structural, not hand-computed.

Idempotent: re-running preserves each dataset's existing `status` (so a resumed
run keeps its progress) unless --force resets everything to "pending".

Spec format (YAML):

    name: main_exp
    max_iters: 10
    threat_model: black_box        # test sequence only; default black_box
    train:
      - {dataset: agentdojo, target: gpt-5-nano, n: 20}
      - {dataset: ipi_arena, target: gpt-5,      n: 15}
    test:
      - {dataset: agentdojo, target: gpt-5-nano, n: 10}

Usage:
    python piminer_plan.py experiments/main_exp.yaml [--force] [--print]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

import yaml

VALID_DATASETS = {"agentdojo", "ipi_arena", "injecagent"}
PROJECT_ROOT = Path(__file__).resolve().parent


def _load_dotenv(path: Path) -> None:
    """Best-effort load of KEY=VALUE lines from .env into os.environ (no override).

    The launchers read provider keys from the environment (with the secrets living
    in the gitignored .env); the planner needs the same view so it can mark a test
    row 'skipped_no_key' when its target's key is absent.
    """
    try:
        text = path.read_text()
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, sep, val = line.partition("=")
        if not sep:
            continue
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def _target_key_available(target_model: str) -> bool:
    """Whether the env (after _load_dotenv) holds a usable key for this target.

    Mirrors the provider→key mapping in benchmarks/ipi_arena/providers.py. Unknown
    providers are not gated (returns True) so a new target is never silently skipped.
    """
    m = target_model.lower()
    if m.startswith(("gpt-", "o1", "o3", "o4", "chatgpt")):
        names = ("OPENAI_API_KEY",)
    elif m.startswith("deepseek"):
        names = ("DEEPSEEK_API_KEY",)
    elif m.startswith("gemini"):
        names = ("GEMINI_API_KEY", "GOOGLE_API_KEY")
    elif m.startswith("claude"):
        names = ("ANTHROPIC_API_KEY", "PIMINER_TARGET_ANTHROPIC_API_KEY")
    else:
        return True
    return any(os.environ.get(n) for n in names)


def _norm_dataset(d: str) -> str:
    d = str(d).strip().lower()
    if d in ("ipiarena", "ipi-arena", "ipi"):
        d = "ipi_arena"
    if d in ("inject-agent", "inject_agent", "injectagent", "inject"):
        d = "injecagent"
    if d not in VALID_DATASETS:
        sys.exit(f"[piminer_plan] ERROR: dataset {d!r} not one of {sorted(VALID_DATASETS)}")
    return d


def _load_existing_status(plan_path: Path, list_key: str) -> dict:
    """Resolve a prior status for each (run_dir | dataset+target) so re-runs keep
    progress even when the sequence is REORDERED.

    Returns a dict with two sub-maps:
        "by_run_dir": {run_dir -> status}                 (exact, position-sensitive)
        "by_id":      {(dataset, target_model) -> status} (stable under reorder)

    `run_dir` embeds the list position `k` (``iterative_attack_<k>_<ds>_<tgt>``), so reordering
    the train/test list changes every entry's `run_dir` and a pure run_dir lookup
    silently resets completed datasets to 'pending'. The benchmark+target identity
    does NOT move when the list is reordered, so we fall back to it. We still prefer
    the exact run_dir match first (no behavior change when nothing was reordered).
    """
    empty = {"by_run_dir": {}, "by_id": {}}
    if not plan_path.exists():
        return empty
    try:
        prev = json.loads(plan_path.read_text())
    except Exception:
        return empty
    by_run_dir, by_id = {}, {}
    for e in prev.get(list_key, []):
        st = e.get("status", "pending")
        if e.get("run_dir"):
            by_run_dir[e["run_dir"]] = st
        key = (e.get("dataset"), e.get("target_model"))
        if all(key):
            by_id[key] = st            # last occurrence wins (lists have no dups today)
    return {"by_run_dir": by_run_dir, "by_id": by_id}


def _build_sequence(items, *, phase, name, base_offsets, force, prev_status,
                    holdout_dirs=None):
    """Return (list-of-dataset-dicts, per-benchmark-max-n).

    phase: "pim_train" or "pim_test" (drives run_dir root).
    base_offsets: the shared offset per benchmark for THIS phase (0 for train;
        per-benchmark max train n for test). Every entry on a benchmark uses the
        SAME offset — the sample window is shared across target LLMs.
    holdout_dirs: optional {benchmark -> [train run_dir, ...]}. When supplied
        (the TEST phase), each test entry on a benchmark gets `holdout_from` set
        to those train run-dirs, so the orchestrator builds an id-based held-out
        complement (full pool MINUS the exact trained rows) instead of slicing by
        offset. This keeps test provably disjoint from train by row identity,
        robust to any suite-set or shuffle differences between the runs (plain
        offset arithmetic would not be).

    Returns the per-benchmark max `n` so the caller can place the test window
    after the train window.
    """
    run_root = f"eval_results/{phase}/{name}"
    holdout_dirs = holdout_dirs or {}
    nmax = defaultdict(int)                # per-benchmark max n (window size)
    seen_n = defaultdict(set)              # per-benchmark distinct n (consistency check)
    out = []
    for i, raw in enumerate(items or [], start=1):
        ds = _norm_dataset(raw["dataset"])
        tgt = str(raw["target"]).strip()
        n = int(raw["n"])
        if n <= 0:
            sys.exit(f"[piminer_plan] ERROR: {phase} item {i} has non-positive n={n}")
        offset = base_offsets.get(ds, 0)   # shared per benchmark — NOT advanced per target
        # Optional explicit per-entry offset: slice the fixed window [offset, offset+n)
        # directly. Overrides the auto-placed window AND disables id-based holdout for
        # this entry (offset-based disjointness instead), so a test-only spec can target
        # a fixed held-out window without needing on-disk training run-dirs.
        explicit_offset = raw.get("offset")
        if explicit_offset is not None:
            offset = int(explicit_offset)
        run_dir = f"{run_root}/iterative_attack_{i:02d}_{ds}_{tgt}"
        # Carry forward real progress; (re)derive only the non-terminal states
        # (pending / skipped_no_key) from whether this target's key is present, so
        # the skip survives reindexing and clears automatically once a key is added.
        # Prefer the exact run_dir match; fall back to the (dataset, target) identity
        # so a REORDERED list (which changes every run_dir) still keeps 'complete'.
        if force:
            status = "pending"
        else:
            status = prev_status["by_run_dir"].get(run_dir)
            if status is None:
                status = prev_status["by_id"].get((ds, tgt), "pending")
        if status in ("pending", "skipped_no_key"):
            status = "pending" if _target_key_available(tgt) else "skipped_no_key"
        entry = {
            "k": i,
            "dataset": ds,
            "target_model": tgt,
            "n_samples": n,
            "sample_offset": offset,
            "run_dir": run_dir,
            "status": status,
        }
        ho = holdout_dirs.get(ds)
        if ho and explicit_offset is None:
            # id-based disjointness; sample_offset is ignored by the orchestrator
            # in this mode but kept for human reference. Skipped when an explicit
            # per-entry offset is given (offset-based disjointness takes over).
            entry["holdout_from"] = ho
        out.append(entry)
        nmax[ds] = max(nmax[ds], n)
        seen_n[ds].add(n)
    for ds, ns in seen_n.items():
        if len(ns) > 1:
            print(f"[piminer_plan] WARN: {phase} has differing sample counts on '{ds}' "
                  f"({sorted(ns)}); the shared window is sized to max={max(ns)} so all "
                  f"targets overlap and stay disjoint from the other phase.", file=sys.stderr)
    return out, nmax


def _print_table(title, rows):
    print(f"\n{title}")
    print(f"  {'k':>2}  {'dataset':<10} {'target':<18} {'n':>4} {'offset':>7}  status")
    for r in rows:
        print(f"  {r['k']:>2}  {r['dataset']:<10} {r['target_model']:<18} "
              f"{r['n_samples']:>4} {r['sample_offset']:>7}  {r['status']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Expand an experiment spec into train+test plan files.")
    ap.add_argument("spec", help="Path to the experiment YAML spec.")
    ap.add_argument("--force", action="store_true",
                    help="Reset every dataset's status to 'pending' (discard prior progress).")
    ap.add_argument("--print", dest="show", action="store_true",
                    help="Print the resolved sequences without writing files.")
    args = ap.parse_args()

    _load_dotenv(PROJECT_ROOT / ".env")  # so _target_key_available sees .env keys

    spec_path = Path(args.spec)
    if not spec_path.exists():
        sys.exit(f"[piminer_plan] ERROR: spec not found: {spec_path}")
    spec = yaml.safe_load(spec_path.read_text()) or {}

    name = str(spec.get("name") or spec_path.stem).strip()
    max_iters = int(spec.get("max_iters", 10))
    # Optional per-phase override; falls back to the shared max_iters when absent.
    test_max_iters = int(spec.get("test_max_iters", max_iters))
    threat_model = str(spec.get("threat_model", "black_box")).strip()
    if not spec.get("train") and not spec.get("test"):
        sys.exit("[piminer_plan] ERROR: spec has neither a 'train' nor a 'test' sequence.")

    train_plan_path = PROJECT_ROOT / f"eval_results/pim_train/{name}/train_plan.json"
    test_plan_path = PROJECT_ROOT / f"eval_results/pim_test/{name}/test_plan.json"

    # --- TRAIN sequence: shared offset 0 per benchmark (same samples across targets) ---
    train_rows, train_nmax = _build_sequence(
        spec.get("train"), phase="pim_train", name=name,
        base_offsets={}, force=args.force,
        prev_status=_load_existing_status(train_plan_path, "training_datasets"),
    )
    # Per-benchmark train run-dirs: the TEST phase holds these out by row id, so
    # the held-out set is disjoint from EVERY trained row on that benchmark
    # (targets share the same trained window, so any one run-dir suffices, but we
    # pass them all so disjointness survives even a partial/re-planned train run).
    train_dirs_by_ds: dict = defaultdict(list)
    for r in train_rows:
        train_dirs_by_ds[r["dataset"]].append(r["run_dir"])
    # --- TEST sequence: id-based held-out complement of the trained rows ---
    test_rows, _ = _build_sequence(
        spec.get("test"), phase="pim_test", name=name,
        base_offsets=dict(train_nmax), force=args.force,
        prev_status=_load_existing_status(test_plan_path, "test_datasets"),
        holdout_dirs=dict(train_dirs_by_ds),
    )

    if args.show:
        print(f"[piminer_plan] experiment '{name}'  max_iters={max_iters}  test_max_iters={test_max_iters}  threat_model={threat_model}")
        if train_rows:
            _print_table("TRAIN sequence:", train_rows)
        if test_rows:
            _print_table("TEST sequence (offsets disjoint from training):", test_rows)
        print("\n[piminer_plan] --print: no files written.")
        return 0

    written = []
    if train_rows:
        train_plan = {"train_name": name, "max_iters": max_iters,
                      "training_datasets": train_rows}
        train_plan_path.parent.mkdir(parents=True, exist_ok=True)
        train_plan_path.write_text(json.dumps(train_plan, indent=2))
        written.append(train_plan_path)
        _print_table(f"TRAIN sequence -> {train_plan_path.relative_to(PROJECT_ROOT)}", train_rows)
    if test_rows:
        test_plan = {"test_name": name, "max_iters": test_max_iters,
                     "threat_model": threat_model, "test_datasets": test_rows}
        test_plan_path.parent.mkdir(parents=True, exist_ok=True)
        test_plan_path.write_text(json.dumps(test_plan, indent=2))
        written.append(test_plan_path)
        _print_table(f"TEST sequence -> {test_plan_path.relative_to(PROJECT_ROOT)}", test_rows)

    print("\n[piminer_plan] wrote:")
    for p in written:
        print(f"  {p.relative_to(PROJECT_ROOT)}")
    print("\nNext:")
    if train_rows:
        print(f"  ./piminer_train_parallel.sh eval_results/pim_train/{name}")
    if test_rows:
        print(f"  PIM_WAVE_SIZE=5 ./piminer_test_parallel.sh eval_results/pim_test/{name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
