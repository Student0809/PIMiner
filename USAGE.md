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

## 使用 ChatGPT 订阅运行 Attacker / Router

安装官方 Codex CLI（`npm install -g @openai/codex`），用执行脚本的同一个系统用户运行
`codex login`，在浏览器中登录 ChatGPT；无浏览器服务器可以使用 `codex login --device-auth`。
`codex login status` 应显示 `Logged in using ChatGPT`。订阅访问受账户的 Codex 额度及模型权限限制。

```bash
# 按原流程生成实验计划
python piminer_plan.py experiments/main_exp.yaml

# 训练：Attacker、Router、digest 全部使用 Codex 的订阅登录
PIM_AGENT_BACKEND=codex PIM_WAVE_SIZE=2 PIM_EFFORT=high \
  bash piminer_train_parallel.sh eval_results/pim_train/main_exp

# 测试：Attacker、Router 使用 Codex，策略库保持冻结
PIM_AGENT_BACKEND=codex PIM_WAVE_SIZE=2 PIM_DATASET_CONC=1 PIM_EFFORT=low \
  bash piminer_test_parallel.sh eval_results/pim_test/main_exp
```

运行目录以 YAML 的 `name` 字段为准。`PIM_AGENT_MODEL` 可以显式指定账户可用的 GPT/Codex
模型；不设置时使用 Codex CLI 默认配置的模型。训练的默认 effort 是 `xhigh`，测试是 `low`，
可以用 `PIM_EFFORT` 调整为所选模型支持的值。后端默认为 `claude`，原有调用方式仍然可用。

Codex 后端以当前系统用户启动，不需要 `claudeuser`。启动前会检查 ChatGPT 登录，拒绝 API key
登录。它不会读取 `.claude/settings.json` 中的 Claude 模型配置；`.claude/commands/step.md` 和
`route.md` 仍作为共用的协议文件读取，`/digest` 则被展开成完整指令。digest 的项目记忆保存在
`eval_results/codex_memory/`。脚本沿用原有无人值守执行权限，因此应在专用实验环境中运行。

Target 仍通过原有 provider API 运行，不使用 Attacker/Router 的订阅额度。原有 `.env` 中的
`OPENAI_API_KEY` 会隔离到 `PIMINER_TARGET_OPENAI_API_KEY`，只在 `submit` 的 Target 调用中
恢复；也可以直接配置后者。`OPENAI_BASE_URL`、`OPENAI_ORG_ID`、`OPENAI_PROJECT_ID` 同样隔离，
其显式 Target 配置名是在前面加 `PIMINER_TARGET_`。Codex 调用会移除 `CODEX_API_KEY`，并强制
使用 ChatGPT 登录。日志保留 Codex JSONL，终端显示简短的执行进度和错误。

官方说明：[登录认证](https://learn.chatgpt.com/docs/auth)、
[非交互执行](https://learn.chatgpt.com/docs/non-interactive-mode)。
