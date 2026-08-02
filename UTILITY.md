# PIMiner — Utility Commands

Housekeeping commands the user can issue in natural language. These are
distinct from the two canonical *run* entry modes documented in
`USAGE.md` (training / test) — utility commands operate on
PIMiner's state itself, not on benchmark samples.

---

## Reset strategy library

> Reset PIMiner's strategy library to empty. Keep only the structure template.

### What the command does

Clears every learned strategy from `strategy_library/`, leaving only the
canonical structure file. The agent should produce the same result as a
fresh repository clone in terms of routable strategies — i.e., zero
strategies for the router to pick from, only the structural reference
the digest reads when authoring new files.

After this command, the next training run starts from a **true cold
start**: routing falls back to a single per-sample strategy (or whatever
the orchestrator's fallback path produces), the inner attacker has no
prior in-context examples to lean on, and every hit the digest captures
goes into a brand-new strategy file written from the template.

### What "the structure template" is

The single file `strategy_library/_TEMPLATE.md`. It is preserved by every
reset because:

1. Its filename begins with `_`, so the orchestrator's discovery glob
   `*_attack_strategy_*.md` skips it — the router and inner attacker
   never see it at run time.
2. The digest reads it as the structural reference when authoring new
   strategy files. Without it, the digest would have no schema for
   section headings, frontmatter, or required subsections.

The template defines these mandatory sections (in order):

| Section heading | Purpose |
|---|---|
| `# <title>` + intro paragraph | File description — what mechanism, against which target class |
| `## Recommended target-LLM scope` | Which target models this strategy applies to (router signal) |
| `## Recommended user-task / injected-task scope` | Which (user_task, injection_task) shapes this strategy applies to (router signal) |
| `## The <strategy_short_name> template (N moves)` | The general strategy / abstract recipe |
| `## In-context examples (M successful attacks against <target>)` | All documented hits with `### Example N` subsections |
| `## Strategy fingerprint, in one sentence` | A compact table the router scans to break ties |
| `## When this strategy is expected to fail` | Documented failure modes |
| `## Notes for iterative attack initialization with this strategy` | Seed-prompt guidance for the inner attacker |

Two extra sections may appear when warranted: a `## Why this mechanism is
distinct ...` contrast section (for novel strategies whose mechanism
overlaps a sibling's), and a `---` separator before the in-context
examples block. Both are documented inline in `_TEMPLATE.md`.

### What the agent does to honor the command

1. **List** the files about to be removed:

   ```bash
   ls strategy_library/*_attack_strategy_*.md 2>/dev/null
   ```

   Report the count and filenames to the user. If the list is empty,
   tell the user there's nothing to remove and stop.

2. **Backup** the current library to a timestamped directory (this is
   the user's escape hatch — resets are otherwise irreversible because
   the agent does not undo digest history):

   ```bash
   BACKUP_DIR="eval_results/strategy_library_backups/reset_<run_label>"
   mkdir -p "$BACKUP_DIR"
   cp strategy_library/*_attack_strategy_*.md "$BACKUP_DIR/" 2>/dev/null
   cp strategy_library/_TEMPLATE.md "$BACKUP_DIR/" 2>/dev/null
   ```

   `<run_label>` should be descriptive (e.g. `pre_pilot3pairs_train`,
   `before_clean_eval`) — ask the user for it if not specified.

3. **Delete** every strategy file *except* the template:

   ```bash
   find strategy_library -maxdepth 1 -name '*_attack_strategy_*.md' -delete
   ```

   (Glob-matched deletion: the underscore-prefixed `_TEMPLATE.md` does
   not match `*_attack_strategy_*.md` and is safe.)

4. **Verify**:

   ```bash
   ls strategy_library/
   ```

   Expected output: only `_TEMPLATE.md`.

5. **Report** ONE line: `strategy library reset: <N> file(s) backed up
   to <BACKUP_DIR>, strategy_library/ now contains only _TEMPLATE.md.`

### When to use

- Before starting a clean training run that should NOT inherit any prior
  digest edits (e.g., the headline experiment for the paper).
- After a misconfigured training run polluted the library and you want
  to recover from a backup rather than carry the bad edits forward.
- Before publishing the repo as a reproducible artifact — the library
  should be in a known state at publication time (typically: either
  empty, or the exact committed snapshot used to produce the paper's
  numbers).

### What this command does NOT do

- It does not touch `eval_results/` (run dirs, snapshots, audits all
  remain).
- It does not touch `strategy_library_post/` snapshots saved inside any
  past training run's iterative-attack directories — those remain as the audit
  trail of what training produced.
- It does not modify `_TEMPLATE.md` itself.
- It cannot be invoked partway through a training or test run — wait for the run
  to finish (or kill it) before resetting.

---

<!--
Future utility commands can be added below as additional H2 sections
with the same shape: command-line natural-language form on top, then
"What the command does", "What the agent does to honor the command",
"When to use", "What this command does NOT do".
-->
