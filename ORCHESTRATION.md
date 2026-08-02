# PIMiner — orchestration & utility reference

> Relocated out of `CLAUDE.md` so it is **not** auto-loaded into every Claude Code
> session (attacker sessions re-read project memory each turn; this content is
> only needed when *dispatching* a run or a utility command). Read this file when
> the user asks to launch a training/test run or issues a housekeeping command.

## Canonical entry points

PIMiner is driven entirely from natural language. There are **two** entry modes — pick whichever matches the user's command shape. Full slot grammar and worked examples live in `USAGE.md`.

For both modes: do not ask follow-up questions about parameters that are present; if a *required* slot is missing, ask for ONLY that slot.

**Training and test sequences are defined in one place: `experiments/<name>.yaml`.** A single spec lists the `train:` sequence and the `test:` sequence (each item = `{dataset, target, n}`); `python piminer_plan.py experiments/<name>.yaml` expands it into `eval_results/pim_train/<name>/train_plan.json` and `eval_results/pim_test/<name>/test_plan.json`, auto-computing `sample_offset`, `run_dir`, and `status`. **`sample_offset` is keyed by benchmark only, not by target**: every target on a benchmark trains on the SAME samples (offset 0) — training across models is the point — and the test window is placed right after the train window on each benchmark (test offset = max train `n` on that benchmark), so train and test never overlap while targets share samples. The parallel drivers `piminer_train_parallel.sh` / `piminer_test_parallel.sh` consume those plan files. Both modes below use this flow.

### Training phase (sequence of training_datasets; digest after each)

**The training sequence (and, in the same file, the test sequence) is defined ONCE in an experiment spec** — `experiments/<name>.yaml` — and expanded into the driver plan files by `piminer_plan.py`. The parallel bash driver `piminer_train_parallel.sh` then runs the whole sequence: per dataset it inits (router + cold-start fallback) → routes → attacks in parallel (rolling/wave) → digests → snapshots `strategy_library_post/` → marks complete.

Spec format (`experiments/<name>.yaml`):

```yaml
name: <name>
max_iters: <max_iters>
threat_model: black_box          # used by the TEST sequence; ignored by train
train:
  - {dataset: <benchmark>, target: <target>, n: <N>}
  - ...
test:                             # optional here — the test phase consumes it
  - {dataset: <benchmark>, target: <target>, n: <N>}
```

Dispatch:

1. If the user gave a natural-language training command (the legacy shape — "Train PIMiner. iterative attack iterations: N. Training datasets: 1. …"), translate it into `experiments/<name>.yaml`: each numbered item → one `train:` entry (`n` = sample count, `dataset` = benchmark, `target` = target model). Pick `<name>` from a "Train name:" clause or a descriptive default, and tell the user the path. If the user already maintains a spec, just edit it.

2. Build the plans (idempotent — preserves prior `status`; `--force` resets):

   ```bash
   python piminer_plan.py experiments/<name>.yaml
   ```

   This writes `eval_results/pim_train/<name>/train_plan.json` (and the test plan if a `test:` block is present). `sample_offset` is auto-computed per benchmark (offset 0 for every training target — the training set is shared across target LLMs by design). **Router + cold-start:** when `strategy_library/` already holds strategies the driver inits in `router` mode (`/route` picks per sample, with `_template_cold_start` registered as the from-scratch fallback); the first dataset on an empty library inits as plain `cold_start`. Because the router needs the library populated by earlier digests, training runs **sequentially over datasets** (parallelism is WITHIN a dataset's samples, not across datasets).

3. Run the driver (concurrency + scheduling via env):

   ```bash
   PIM_WAVE_SIZE=<conc> PIM_ATTACK_MODE=rolling ./piminer_train_parallel.sh eval_results/pim_train/<name>
   ```

   It is resumable: re-running skips datasets already `complete` and polls on-disk sample state within a dataset. Per the run-to-completion mandate, launch it (optionally `run_in_background: true`) and let it finish; do not pause mid-run.

4. When the driver prints `ALL DONE`, report per-dataset ASR (read each `iterative_attack_NN/results.json` or recompute from `samples/`) and ONE final line: `training complete: <K> datasets; strategy_library evolved across <K> snapshots under eval_results/pim_train/<name>/.`

### Test phase (strategy library frozen; black-box; parallel)

Test runs are **frozen** (the strategy library is never digested/mutated) and **black-box** (the attacker sees ONLY the target's final output text + the binary security verdict per iter — never the trajectory, tool calls, or intermediate steps; this mirrors PISmith's threat model). The trajectory is redacted both in the `next` prompt and on disk (`samples/NNN.json`), so a shell-capable attacker session physically cannot read it.

The test sequence is the `test:` block of the **same** `experiments/<name>.yaml` used for training, expanded by `piminer_plan.py`. `piminer_test_parallel.sh` then runs init (frozen + black-box) → route → parallel attack (rolling/wave) → results-collection per dataset, with no digest and no snapshot. It also verifies a SHA-256 manifest of `strategy_library/` after every dataset and aborts (exit 7) on any drift.

Dispatch:

1. **Disjointness is automatic and id-based.** `piminer_plan.py` stamps each `test:` entry with `holdout_from` = the training run-dirs on the same benchmark. At init the orchestrator builds the **full** pool (ipi_arena = tool+coding+browser) and removes the EXACT rows those training runs sampled (matched by `(suite, user_task, injection_task, step)` key), then takes the first `n` of the complement. This guarantees test ⟂ train by row identity, robust to any suite-set or shuffle differences between the runs (plain offset arithmetic would not be). `sample_offset` is kept in the plan for reference but ignored when `holdout_from` is present. Asking for more samples than the complement holds is a hard error (no silent shrink). You do not hand-compute anything. If the user adds test datasets to the spec, just rebuild:

   ```bash
   python piminer_plan.py experiments/<name>.yaml
   ```

   This writes `eval_results/pim_test/<name>/test_plan.json` (with `threat_model` from the spec, default `black_box`).

2. Run the driver:

   ```bash
   PIM_WAVE_SIZE=<conc> PIM_ATTACK_MODE=rolling ./piminer_test_parallel.sh eval_results/pim_test/<name>
   ```

   **All target models are evaluated CONCURRENTLY.** Because the library is frozen (test never digests), test datasets have no inter-dataset dependency — every `test:` entry runs as its own backgrounded pipeline (init → route → attack → results) at the same time. `PIM_DATASET_CONC` caps how many datasets run at once (default `0` = all pending); total in-flight attacker sessions ≈ `PIM_DATASET_CONC × PIM_WAVE_SIZE`, so size both for your API quota (e.g. 8 targets × wave 5 = 40 sessions). Shared writes to `test_results.json` / `test_plan.json` are flock-serialized. It inits each dataset `--frozen-strategies --threat-model black_box`, routes, attacks in parallel over samples, and writes per-dataset ASR to `eval_results/pim_test/<name>/test_results.json`. **No** digest, **no** snapshot — `strategy_library/` MUST NOT change (and is manifest-verified at start and after each dataset).

3. Report ONE line per dataset from `test_results.json`: `test dataset <k>/<K> complete: <benchmark>/<target> asr=<x.xx> (black-box); strategy_library not modified.` Then a final line: `test complete: <K> datasets; black-box; library frozen+verified; ASR in eval_results/pim_test/<name>/test_results.json.`

## Utility commands

Housekeeping commands that operate on PIMiner's state (not on benchmark samples) are documented in `UTILITY.md`. Most importantly:

- **Reset strategy library** — user says *"Reset PIMiner's strategy library to empty. Keep only the structure template. Backup label: `<run_label>`."* The agent must back up the current `strategy_library/*_attack_strategy_*.md` files to `eval_results/strategy_library_backups/reset_<run_label>/` BEFORE deleting them, then verify only `_TEMPLATE.md` remains. Full dispatch protocol in `UTILITY.md` → "Reset strategy library". Do NOT delete `strategy_library/_TEMPLATE.md` — it is the structural reference the digest reads when writing new strategy files.

If the user issues a utility command not documented in `UTILITY.md`, ask for clarification before executing — utility commands frequently mutate persistent state and are not safe to improvise.
