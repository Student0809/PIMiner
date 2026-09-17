import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'iterative_attack_orchestrator/agent_cli.py'
spec = importlib.util.spec_from_file_location('agent_cli', CLI)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class AgentCLITest(unittest.TestCase):
    def test_target_credentials_are_separate(self):
        source = {'OPENAI_API_KEY': 'ordinary-target', 'PIMINER_TARGET_OPENAI_API_KEY': 'explicit-target',
                  'OPENAI_BASE_URL': 'https://target.invalid', 'CODEX_API_KEY': 'agent-api', 'PATH': '/bin'}
        env = launcher.codex_environment(source)
        self.assertNotIn('OPENAI_API_KEY', env)
        self.assertNotIn('CODEX_API_KEY', env)
        self.assertNotIn('OPENAI_BASE_URL', env)
        self.assertEqual(env['PIMINER_TARGET_OPENAI_API_KEY'], 'explicit-target')
        self.assertEqual(env['PIMINER_TARGET_OPENAI_BASE_URL'], 'https://target.invalid')
        self.assertEqual(source['OPENAI_API_KEY'], 'ordinary-target')

    def test_digest_is_expanded(self):
        prompt = launcher.expand_prompt('/digest eval_results/example')
        self.assertNotIn('$ARGUMENTS', prompt)
        self.assertNotIn('<MEMORY_DIR>', prompt)
        self.assertIn('digest --run-dir eval_results/example', prompt)
        self.assertIn('eval_results/codex_memory', prompt)
        self.assertIn('--finalize', prompt)

    def test_exec_translation_and_login_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'codex'
            fake.write_text('#!' + sys.executable + '\n'
                            'import json, os, sys\n'
                            'if "login" in sys.argv:\n'
                            ' print(os.environ.get("FAKE_AUTH", "Logged in using ChatGPT"))\n'
                            'else:\n'
                            ' print(json.dumps({"argv":sys.argv[1:],"prompt":sys.stdin.read(),'
                            '"key":os.environ.get("OPENAI_API_KEY"),'
                            '"target":os.environ.get("PIMINER_TARGET_OPENAI_API_KEY")}))\n')
            fake.chmod(0o755)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                       PIM_AGENT_BACKEND='codex', OPENAI_API_KEY='test-target')
            env.pop('PIMINER_TARGET_OPENAI_API_KEY', None)
            result = subprocess.run([sys.executable, str(CLI), '-p', 'route this sample',
                                     '--model', 'test-model', '--effort', 'high',
                                     '--dangerously-skip-permissions', '--output-format', 'stream-json',
                                     '--verbose', '--include-partial-messages'], env=env,
                                    capture_output=True, text=True, check=True)
            output = json.loads(result.stdout)
            self.assertIn('--json', output['argv'])
            self.assertIn('--dangerously-bypass-approvals-and-sandbox', output['argv'])
            self.assertIn('forced_login_method="chatgpt"', output['argv'])
            self.assertIn('model_reasoning_effort="high"', output['argv'])
            self.assertIn('test-model', output['argv'])
            self.assertIn('route this sample', output['prompt'])
            self.assertIsNone(output['key'])
            self.assertEqual(output['target'], 'test-target')
            accepted = subprocess.run([sys.executable, str(CLI), '--check'], env=env, capture_output=True)
            self.assertEqual(accepted.returncode, 0)
            env['FAKE_AUTH'] = 'Logged in using an API key'
            rejected = subprocess.run([sys.executable, str(CLI), '--check'], env=env, capture_output=True)
            self.assertEqual(rejected.returncode, 1)

    def test_codex_logs_surface_errors(self):
        events = [{'type': 'item.completed', 'item': {'type': 'command_execution', 'command': 'python route-next'}},
                  {'type': 'turn.failed', 'error': {'message': 'usage_limit_reached'}}]
        result = subprocess.run([sys.executable, str(ROOT / 'iterative_attack_orchestrator/claude_stream_log.py'),
                                 '--prefix', '[test]', '--context', 'router'],
                                input='\n'.join(map(json.dumps, events)), capture_output=True, text=True, check=True)
        self.assertIn('python route-next', result.stdout)
        self.assertIn('usage_limit_reached', result.stdout)


if __name__ == '__main__':
    unittest.main()
