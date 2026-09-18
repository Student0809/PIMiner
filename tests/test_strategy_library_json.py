"""Catch field loss, fence confusion, truncation and unsafe output replacement."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONVERTER = ROOT / 'strategy_library_json/convert.py'

FIXTURE = '''# Example strategy

Original explanation — not a new claim.

## Recommended target-LLM scope

- **Confirmed effective**: model-a — one example.

## Recommended user-task / injected-task scope

- **Prerequisites**: a retrieved text slot.

## Why this mechanism is distinct

Keep the distinction.

## The example template (2 moves)

1. **First move** — Original first step.
2. **Second move** — Original second step.

Optional note stays here.

## In-context examples

### Example 1 — `suite / task / goal` (target: model-a)

An important introductory caveat.

**User task (verbatim)**:
> Summarize the document.
> Preserve this second line.

**Injection goal (verbatim)**:
> Fixture goal.

**Placeholder context** (verbatim):
````text
## Embedded heading
```python
print("data only")
```
### Example 99 — this is embedded data
{INJECTION:slot}
````

**Winning injection text** (iter 2):
```

Literal \\n, "quotes", Unicode 中文.

```

**Resulting target output**: Original result.

**Why this worked on model-a**: Original analysis.

## Strategy fingerprint, in one sentence

| # | Mechanism | Target |
|---|-----------|--------|
| 1 | original | model-a |

## When this strategy is expected to fail

- Original failure condition.

## Notes for PAIR initialization with this strategy

- Original initialization note.

## Unrecognized future section

Do not silently drop this.
'''


class StrategyJSONTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CONVERTER.exists():
            return
        spec = importlib.util.spec_from_file_location('strategy_json_converter', CONVERTER)
        cls.converter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.converter)

    def convert_fixture(self):
        self.assertTrue(CONVERTER.exists(), 'The strategy JSON converter is not implemented yet')
        return self.converter.convert_document(FIXTURE, 'demo_attack_strategy_example_model-a.md')

    def test_named_fields_and_exact_code_text_are_preserved(self):
        doc = self.convert_fixture()
        self.assertEqual(len(doc['examples']), 1)
        ex = doc['examples'][0]
        self.assertEqual(ex['user_task'], 'Summarize the document.\nPreserve this second line.')
        self.assertEqual(ex['injection_goal'], 'Fixture goal.')
        self.assertEqual(ex['target_model'], 'model-a')
        self.assertEqual(ex['benchmark_case'], {'suite': 'suite', 'user_task_id': 'task', 'injection_task_id': 'goal'})
        self.assertIn('### Example 99 — this is embedded data', ex['placeholder_context'])
        self.assertEqual(ex['winning_injection_text'], '\nLiteral \\n, "quotes", Unicode 中文.\n\n')
        self.assertEqual(ex['result'], 'Original result.')
        self.assertEqual(ex['why_it_worked'], 'Original analysis.')
        self.assertIn('introductory caveat', ex['preamble_markdown'])
        self.assertEqual(json.loads(json.dumps(doc))['examples'][0]['winning_injection_text'], ex['winning_injection_text'])

    def test_steps_scope_and_unknown_sections_are_structured(self):
        doc = self.convert_fixture()
        self.assertEqual([x['number'] for x in doc['procedure']['steps']], [1, 2])
        self.assertEqual(doc['procedure']['steps'][0]['name'], 'First move')
        self.assertEqual(doc['scope']['target_models']['items'][0]['label'], 'Confirmed effective')
        self.assertIn('a retrieved text slot', doc['scope']['user_and_injected_tasks']['items'][0]['text'])
        self.assertIn('Original failure condition', doc['failure_conditions']['items'][0]['text'])
        self.assertEqual(doc['fingerprint']['tables'][0]['rows'], [['1', 'original', 'model-a']])
        self.assertEqual(doc['extra_sections'][0]['heading'], 'Unrecognized future section')

    def test_archive_roundtrip_preserves_every_source_character(self):
        doc = self.convert_fixture()
        self.assertEqual(self.converter.restore_markdown(doc), FIXTURE)
        self.assertEqual(self.converter.restore_markdown(self.converter.convert_document(FIXTURE.replace('\n', '\r\n'), 'x.md')), FIXTURE.replace('\n', '\r\n'))

    def test_missing_fields_stay_null_and_template_is_not_evidence(self):
        self.convert_fixture()
        doc = self.converter.convert_document('# Sparse\n\n## In-context examples\n\n### Example 1 — ...\n', '_TEMPLATE.md')
        self.assertEqual(doc['kind'], 'template')
        self.assertIsNone(doc['examples'][0]['winning_injection_text'])
        self.assertIsNone(doc['examples'][0]['target_model'])
        self.assertTrue(doc['warnings'])

    def test_same_length_nested_code_fences_keep_later_examples_visible(self):
        self.convert_fixture()
        text = '''# Nested
## In-context examples
### Example 1 — first (target: model-a)
**Winning injection text**:
```
Before.
```python
print("embedded")
```
After.
```
**Resulting target output**: first result
**Why this worked on model-a**: first analysis
### Example 2 — second (target: model-a)
**Winning injection text**:
```
Second.
```
'''
        doc = self.converter.convert_document(text, 'nested.md')
        self.assertEqual(len(doc['examples']), 2)
        self.assertEqual(doc['examples'][0]['winning_injection_text'], 'Before.\n```python\nprint("embedded")\n```\nAfter.\n')
        self.assertEqual(doc['examples'][0]['result'], 'first result')

    def test_missing_outer_fence_is_recovered_without_rewriting_source(self):
        self.convert_fixture()
        text = '''# Broken source
## In-context examples
### Example 1 — first (target: model-a)
**Placeholder context**:
```
Retrieved Markdown.
```python
print("embedded")
```

**Winning injection text**:
```
Original example.
```
**Resulting target output**: result
**Why this worked on model-a**: analysis
'''
        doc = self.converter.convert_document(text, 'broken.md')
        self.assertEqual(doc['examples'][0]['winning_injection_text'], 'Original example.\n')
        self.assertEqual(doc['examples'][0]['placeholder_context'], 'Retrieved Markdown.\n```python\nprint("embedded")\n```')
        self.assertEqual(self.converter.restore_markdown(doc), text)
        self.assertTrue(any('fence' in warning for warning in doc['warnings']))

    def test_bare_inner_fences_do_not_become_part_of_decoded_payload(self):
        self.convert_fixture()
        text = '''# Bare nested delimiters
## In-context examples
### Example 1 — first (target: model-a)
**Winning injection text**:
```
Original prose.
```
embedded code
```
Final original prose.
```
**Resulting target output**: result
'''
        doc = self.converter.convert_document(text, 'bare.md')
        self.assertEqual(doc['examples'][0]['winning_injection_text'], 'Original prose.\n```\nembedded code\n```\nFinal original prose.\n')

    def test_reference_only_context_is_not_passed_off_as_context_text(self):
        self.convert_fixture()
        text = '''# Reference
## In-context examples
### Example 1 — reference (target: model-a)
**Placeholder context** (verbatim source — full slot at `samples/001.json -> context_with_placeholder`).
**Winning injection text**:
```
Original.
```
'''
        doc = self.converter.convert_document(text, 'reference.md')
        ex = doc['examples'][0]
        self.assertIsNone(ex['placeholder_context'])
        self.assertIn('samples/001.json', ex['placeholder_context_reference'])
        self.assertTrue(ex['field_blocks'][0]['reference_only'])
        self.assertIsNone(ex['field_blocks'][0]['text'])

    def test_cli_exports_checks_and_refuses_unrelated_overwrite(self):
        self.assertTrue(CONVERTER.exists(), 'The strategy JSON converter is not implemented yet')
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            dest = Path(directory) / 'json'
            source.mkdir()
            (source / 'demo_attack_strategy_example_model-a.md').write_text(FIXTURE)
            command = [sys.executable, str(CONVERTER), '--source', str(source), '--dest', str(dest)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((dest / 'strategy.schema.json').exists())
            index = json.loads((dest / 'index.json').read_text())
            self.assertEqual(index['strategy_count'], 1)
            self.assertEqual(index['example_count'], 1)
            checked = subprocess.run(command + ['--check'], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            target = dest / 'demo_attack_strategy_example_model-a.json'
            target.write_text('{"unrelated": true}\n')
            refused = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(target.read_text(), '{"unrelated": true}\n')
            stale = subprocess.run(command + ['--check'], capture_output=True, text=True)
            self.assertNotEqual(stale.returncode, 0)


if __name__ == '__main__':
    unittest.main()
