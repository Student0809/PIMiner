# PIMiner

This repository is the official implementation of the paper
**_Agent Against Agent: An Agentic System for Automatic Prompt Injection Red Teaming_**.
PIMiner is an agentic system for prompt-injection red-teaming against tool-using agents. During training, PIMiner is trained on a sequence of (dataset, target model) pairs and builds a strategy library from scratch. At test time, the learned
strategy library can be directly transferred to a previously unseen target LLM without addi-tional training.

<p align="center">
  <img src="misc/pipeline.jpeg" alt="PIMiner pipeline: Strategy Library → Router → Iterative Attack → Digestor, with an Update loop back to the library" width="500">
</p>

---

## 🔨 Setup environment

PIMiner runs the attacker/router/digest as **Claude Code sessions**, so the
[Claude Code CLI](https://docs.claude.com/en/docs/claude-code) is a hard prerequisite.

**1. Claude Code CLI** (drives the attacker/router; runs on your Claude subscription):

```bash
npm install -g @anthropic-ai/claude-code
claude          # log in once (Max/Pro subscription recommended — the drivers unset
                # ANTHROPIC_API_KEY so attacker/router use subscription auth, not an API key)
```

**2. Python environment** (Python 3.10+):

```bash
conda create -n piminer python=3.10
conda activate piminer
pip install -r requirements.txt
```

---

## 🔑 Set API keys

The attacker/router run on your Claude Code subscription. The **target models** under
attack use per-provider API keys, read from a gitignored `.env` at the repo root:

```bash
cp .env.example .env
# then edit .env:
OPENAI_API_KEY=...                     # gpt-5*, gpt-4*, o* targets (also DeepSeek via OpenAI-compatible)
PIMINER_TARGET_ANTHROPIC_API_KEY=...   # claude-* targets (kept separate from attacker/router auth)
GEMINI_API_KEY=...                     # gemini-2.5-* targets
DEEPSEEK_API_KEY=...                   # deepseek-* targets
```

Only set the keys for the target providers you actually attack.

---

## 📁 Datasets

PIMiner ships with three benchmark adapters; all data and harnesses are included in-tree.

| Benchmark   | Status | Notes |
|-------------|--------|-------|
| `agentdojo` | ✅ ready | `data/agentdojo/agentdojo_injection_steps.jsonl` |
| `injecagent` | ✅ ready | `data/injecagent/injecagent_rows.jsonl` (GPT/OpenAI targets only) |
| `ipi_arena` | ✅ bundled | upstream harness vendored under `data/ipi_arena/repo/` |

The `ipi_arena` upstream benchmark ([GraySwanAI/ipi_arena_os](https://github.com/GraySwanAI/ipi_arena_os), MIT) is vendored in-tree. Install it once so its `ipi_arena_bench` package is importable:

```bash
pip install -e data/ipi_arena/repo
```

---

## 🚀 Quick start

The repo ships a **pre-trained `strategy_library/`**, so you can attack a model right
away — no training needed. This example runs a frozen (black-box) test on `gpt-5`
over `ipi_arena`, on the **fixed held-out test set** (the same set used in the paper).
Open Claude Code in the repo root and ask it, in plain language:

> **User:** Run a PIMiner test on **gpt-5** over `ipi_arena` using the **existing**
> strategy library, on the fixed held-out test set — **sample offset 20, n = 21**. Keep
> the library **frozen** ; use black-box mode; don't train or digest.

Claude Code reads `USAGE.md` / `ORCHESTRATION.md`, writes a one-entry test spec with that
offset, builds its plan with `piminer_plan.py`, runs `piminer_test_parallel.sh`, and
reports the attack success rate (ASR). It reuses the shipped `strategy_library/` as-is.
ASR lands in `eval_results/pim_test/quickstart/test_results.json`.

---

## 🔬 Experiments

Reproduce the full study — train a strategy library **from scratch**, then evaluate it
on held-out cases. Both sequences are defined in one spec, `experiments/main_exp.yaml`:

```yaml
name: main_exp
max_iters: 10
threat_model: black_box            # applies to the test sequence
train:                             # library evolves + digests after each entry
  - {dataset: agentdojo, target: gpt-5-nano,       n: 20}
  - {dataset: ipi_arena, target: claude-haiku-4-5, n: 20}
  ...
test:                              # library FROZEN; held-out samples (auto-disjoint)
  - {dataset: agentdojo, target: gpt-5,      n: 30}
  - {dataset: ipi_arena, target: gpt-5-nano, n: 21}
  ...
```

Drive it from Claude Code in plain language. First reset the shipped library so training
starts cold (this backs the strategies up rather than discarding them):

> **User:** Reset PIMiner's strategy library to empty. Keep only the structure template.
> Backup label: `shipped`.

Then run the experiment in two steps — Claude Code reads `USAGE.md` / `ORCHESTRATION.md`
and handles plan → train, then plan → test. Train first:

> **User:** Train PIMiner over the `train:` sequence in `experiments/main_exp.yaml` —
> digest after each dataset. Report per-dataset ASR.

This builds the plan files with `piminer_plan.py` and runs `piminer_train_parallel.sh`,
evolving `strategy_library/` and snapshotting it to `strategy_library_post/` after each
dataset. Wait for it to finish, then test against the frozen library:

> **User:** Run the frozen black-box `test:` sequence in `experiments/main_exp.yaml`.
> Report per-dataset ASR.

This runs `piminer_test_parallel.sh` and reports ASR from `test_results.json`. The library
is never digested or mutated during test, verified after every
dataset.

Running the two as separate prompts lets you inspect what training learned (the new
strategy files, and each dataset's ASR) before committing to the test sweep — and if a
test run needs re-running, it does not re-train.

**Prefer to run it yourself?** The equivalent explicit commands:

```bash
# 0. reset the shipped library (keeps a backup) so training starts cold
mkdir -p eval_results/strategy_library_backups/shipped
mv strategy_library/*_attack_strategy_*.md eval_results/strategy_library_backups/shipped/

# 1. build the train + test plan files
python piminer_plan.py experiments/main_exp.yaml

# 2. train — evolves strategy_library/, snapshots after each dataset
PIM_WAVE_SIZE=5 PIM_ATTACK_MODE=rolling ./piminer_train_parallel.sh eval_results/pim_train/main_exp

# 3. test — frozen + black-box, all targets in parallel
PIM_WAVE_SIZE=5 PIM_ATTACK_MODE=rolling ./piminer_test_parallel.sh eval_results/pim_test/main_exp
```

Per-dataset ASR lands in `eval_results/pim_test/main_exp/test_results.json`. Both scripts
are **resumable** — re-run to skip completed datasets and pick up on-disk state.

---

## How it works

Each run proceeds per (benchmark, target) dataset:

1. **Init** — sample rows from the benchmark pool into the run directory.
2. **Route** — a router session picks the top-3 candidate strategies per sample
   (`_template_cold_start` is the from-scratch fallback).
3. **Attack** — one attacker session per sample iteratively refines an injection
   (`next` → write `<analysis>+<injection>` → `submit`) until **hit** or **miss**,
   with `PIM_WAVE_SIZE` samples in flight concurrently.
4. **Digest** *(training only)* — distill successful attacks into `strategy_library/`
   and snapshot it as `strategy_library_post/`.

**Training** runs datasets sequentially (the router needs each digest's output) and
**mutates** `strategy_library/`. **Testing** runs all datasets in parallel, is
**frozen**.

---

## ⚙️ Configuration

Driver behavior is controlled by environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `PIM_WAVE_SIZE` | `5` | Concurrent attacker sessions per dataset |
| `PIM_ATTACK_MODE` | `rolling` | `rolling` (refill as samples finish) or `wave` (barrier per wave) |
| `PIM_AGENT_MODEL` | `claude-opus-4-7` | Pinned attacker/router/digest model |
| `PIM_EFFORT` | `xhigh` (train) / `low` (test) | Reasoning effort |
| `PIM_DATASET_CONC` | `0` (all) | *(test only)* max datasets run at once |
| `PIM_TARGETS` | *(all)* | *(test only)* restrict to specific target model name(s) |

Total in-flight sessions ≈ `PIM_DATASET_CONC × PIM_WAVE_SIZE` — size both to your quota.

---

## 🗂️ Repository structure

```
piminer_train_parallel.sh          # training driver (route → attack → digest → snapshot)
piminer_test_parallel.sh           # test driver (frozen + black-box, parallel)
piminer_plan.py                    # expands experiments/*.yaml → train/test plan files
experiments/                       # experiment specs (train: + test: sequences)
iterative_attack_orchestrator/     # the iterative-attack orchestrator (next/submit/route)
benchmarks/                        # agentdojo / ipi_arena / injecagent adapters + rewards
data/                              # benchmark row pools + build/fetch scripts
strategy_library/                  # the learned attack strategies (+ _TEMPLATE.md)
.claude/commands/                  # route.md / step.md / digest.md slash commands
CLAUDE.md, ORCHESTRATION.md, USAGE.md, UTILITY.md   # agent-facing operating docs
user_commands/                     # command recipes for users(train / test / reset)
```

---

## Acknowledgement

PIMiner builds on the [AgentDojo](https://github.com/ethz-spylab/agentdojo),
[InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent), and IPIArena
benchmarks. The
iterative attacker is inspired by [PAIR](https://arxiv.org/abs/2310.08419).

---


