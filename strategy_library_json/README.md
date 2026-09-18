# Structured strategy library

This is an offline, content-preserving JSON export of `../strategy_library`.
It does not replace that directory and does not change the router, attacker,
training scripts, or evaluation scripts. Example commands are **data only**;
the converter never runs them.

## Files

- One same-stem `.json` file for each of the 10 existing strategies.
- `_TEMPLATE.json`: the structural template, with `kind: "template"`.
  Its two illustrative example placeholders are not empirical evidence and
  are excluded from the index's strategy/example totals.
- `strategy.schema.json`: JSON Schema draft 2020-12 for strategy/template files.
- `index.json`: file list, source hashes, example counts, and conversion warnings.
- `convert.py`: repeatable exporter and read-only consistency checker;
  uses only Python's standard library.

## Structure

Each strategy has the following fields:

| Field | Meaning |
| --- | --- |
| `id`, `kind`, `title`, `schema_version` | Stable source-derived identity and export format |
| `source` | Original filename, UTF-8 byte count and SHA-256 |
| `introduction_markdown` | Original introductory explanation |
| `scope.target_models` | Model-scope statements, parsed bullet items and original section |
| `scope.user_and_injected_tasks` | Task/surface/prerequisite statements and parsed items |
| `mechanism_distinction` | Original comparison with other mechanisms |
| `procedure.steps` | Ordered moves, with number, name, text and source Markdown |
| `procedure.markdown` | Complete recipe, including optional notes not in numbered moves |
| `examples` | Independent case objects, in source order |
| `fingerprint.tables` | Table columns and rows; original table is also retained |
| `failure_conditions.items` | Original failure-condition bullets |
| `initialization_guidance.items` | Original iteration/init guidance |
| `extra_sections` | Unrecognized or repeated sections, never silently dropped |
| `source_blocks` | Ordered raw source segments for exact archival reconstruction |
| `warnings` | Missing fields or source-boundary recovery; not model-performance verdicts |

An example independently stores `number`, `heading`, `source_line`,
`target_model`, `benchmark_case`, `user_task`, `injection_goal`,
`placeholder_context`, `placeholder_context_reference`,
`winning_injection_text`, `result`, and `why_it_worked`.
`preamble_markdown` preserves commentary before the named fields.
`field_blocks` retains each field's label, annotations, original Markdown,
decoded text and `reference_only` flag.

## Content fidelity and caveats

- No strategy mechanisms or evidence claims have been rewritten or strengthened.
  Human-readable natural language remains inside explicit fields and arrays.
- Fenced code payloads retain their literal newlines, quotes, backslashes and
  Unicode characters, including inner Markdown/code fences. JSON serialization
  escapes are decoded by a normal JSON parser; do not use the serialized
  representation as a payload.
- Source prose marked "verbatim" sometimes contains summaries or ellipses.
  The export preserves these as supplied; it does not recover missing text or
  certify that a source claim is correct.
- Some contexts consist of references to run/sample files or are already
  truncated in the source. These are retained, not automatically dereferenced.
  `reference_only: true` marks cases with a pointer/description in the field
  annotation and no context body: `placeholder_context` is then `null`, and
  `placeholder_context_reference` retains the pointer/description. Other partially quoted contexts are not
  certified complete merely because this flag is false.
- Missing information remains `null`, with a warning. Template placeholders
  remain placeholders, not real examples.
- The original `ipi_arena_attack_strategy_false_history_forge_gpt-5.md`
  has an unclosed outer context fence. Parsing recovers at the following
  ordered protocol field and records a warning; archival source is unchanged.
- `source_blocks` intentionally duplicates some parsed content to guarantee
  fidelity. It is an audit archive, not recommended model-prompt material.
  Reconstruct the exact source with `restore_markdown(document)` from
  `convert.py`, or concatenate the blocks' `markdown` values in order.
- This conversion is not an attack-effectiveness experiment. It makes no
  claim that sending raw JSON to a model matches Markdown performance.

## Verification and re-export

From the repository root, check that all exports match the current source:

```bash
/root/miniconda3/envs/piminer/bin/python strategy_library_json/convert.py --check
```

The checker is read-only and also checks the index and schema against the
converter's definitions. The schema can additionally be validated with a
draft-2020-12 JSON Schema validator; it applies to strategy/template files,
not `index.json` or the schema file itself.

To export changed source content, choose a fresh directory:

```bash
/root/miniconda3/envs/piminer/bin/python strategy_library_json/convert.py \
  --dest /tmp/piminer-strategy-json-new
```

The exporter refuses to overwrite existing different files. An unchanged
export can be run again safely. It never updates the source Markdown.

Run the offline regression tests:

```bash
PYTHONDONTWRITEBYTECODE=1 /root/miniconda3/envs/piminer/bin/python \
  -m unittest discover -s tests -p test_strategy_library_json.py -v
```
