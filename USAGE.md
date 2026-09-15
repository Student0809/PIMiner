# Using PIMiner

PIMiner is driven entirely from natural language inside Claude Code. You do
not invoke the orchestrator CLI directly and you do not type the per-iter
slash commands — the agent reads this file together with `CLAUDE.md` and
the procedures under `.claude/commands/` to translate your request into the
full route → attack → digest pipeline.

There are **two entry modes**:

| Mode | When to use | Strategy library |
|------|-------------|------------------|
| **Training phase** | Build up the strategy library across a sequence of (dataset, target) training_datasets | Mutated *and* snapshotted after each training_dataset |
| **Test phase** | Held-out evaluation of the trained agent | **Frozen** — digest is disabled |

---

## Training and Test via one experiment spec

Both the training sequence and the test sequence are defined in **one file**, `experiments/<name>.yaml`. You edit that file; the rest is two commands.

### The spec

```yaml
name: main_exp
max_iters: 10
threat_model: black_box          # test sequence only (frozen + black-box)
train:                           # library evolves + digests after each
  - {dataset: agentdojo, target: gpt-5-nano,       n: 20}
  - {dataset: agentdojo, target: gpt-5,            n: 20}
  - {dataset: ipi_arena, target: claude-haiku-4-5, n: 15}
test:                            # library FROZEN; held-out samples
  - {dataset: agentdojo, target: gpt-5-nano, n: 10}
  - {dataset: ipi_arena, target: gpt-5,      n: 10}
```

Build the plan files (idempotent — preserves prior `status`; `--force` resets; `--print` dry-runs):

```bash
python piminer_plan.py experiments/main_exp.yaml
```

This writes `eval_results/pim_train/main_exp/train_plan.json` and `eval_results/pim_test/main_exp/test_plan.json`. **`sample_offset` is auto-computed and keyed by benchmark only, not by target**: every target on a benchmark trains on the *same* samples (offset 0) — that's the point of training across models — and the test window is placed right after the train window on each benchmark (test offset = max train `n` on that benchmark). So train and test never reuse a sample, while different targets on the same benchmark do. You never hand-compute offsets.

### Run training

```bash
PIM_WAVE_SIZE=5 PIM_ATTACK_MODE=rolling ./piminer_train_parallel.sh eval_results/pim_train/main_exp
```

Per dataset (sequentially, since the router needs earlier digests) it inits (router + cold-start fallback) → routes → attacks samples in parallel → digests (mutates `strategy_library/`) → snapshots `strategy_library_post/` → marks `complete`. Resumable: re-running skips completed datasets.

### Run test

```bash
PIM_WAVE_SIZE=5 PIM_ATTACK_MODE=rolling ./piminer_test_parallel.sh eval_results/pim_test/main_exp
```

Same parallel machinery but **frozen + black-box**: no digest, no snapshot. The attacker sees only the target's final output (text + final tool call[s]) and the binary verdict — never the trajectory (redacted in-prompt and on disk). A SHA-256 manifest of `strategy_library/` is verified after every dataset; any drift aborts the run (exit 7). Per-dataset ASR is written to `eval_results/pim_test/main_exp/test_results.json`.

### Where results go

```
eval_results/pim_train/<name>/
├── train_plan.json
├── iterative_attack_01_agentdojo_gpt-5-nano/
│   ├── samples/ attempts/ routing/ strategies/ config.json digest_audit.md
│   └── strategy_library_post/    ← snapshot of strategy_library/ AFTER this dataset's digest
└── ...
eval_results/pim_test/<name>/
├── test_plan.json
├── test_results.json             ← per-dataset ASR (black-box)
└── iterative_attack_01_.../  (no strategy_library_post — library is frozen)
```

The mutable source of truth is `<repo_root>/strategy_library/`; train snapshots are read-only audit artifacts; test never touches it.

---

## What the agent does NOT do

- It does not silently substitute fewer iterations or fewer samples than you asked for.
- It does not declare a sample "unhittable" or stop early on a 0% partial result.
- It does not write attack attempts in batched form across samples — iterative attack is sample-major with per-sample isolation.
- **In test mode**, it does not write to `strategy_library/` under any circumstance, even if Phase 2 finds hits. The frozen-library guard fires inside the orchestrator (exit code 4), not just the slash command, so accidental digest invocations are rejected at the source.
