import ast
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TrainingPermissionsTest(unittest.TestCase):
    def logger(self):
        tree = ast.parse((ROOT / 'iterative_attack_orchestrator/iterative_attack_claude_code.py').read_text())
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_append_run_log']
        self.assertEqual(len(nodes), 1, 'missing non-fatal logger')
        namespace = {'sys': sys}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<logger>', 'exec'), namespace)
        return namespace['_append_run_log']

    def test_append(self):
        logger = self.logger()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.log'
            path.write_text('previous\n')
            logger(str(path), 'result\n')
            self.assertEqual(path.read_text(), 'previous\nresult\n')

    def test_oserror_warns_without_raising(self):
        logger = self.logger()
        with tempfile.TemporaryDirectory() as directory:
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                logger(directory, 'result\n')
            self.assertIn('WARNING', error.getvalue())
            self.assertIn(directory, error.getvalue())

    def test_summary_persists_and_returns_json_despite_log_failure(self):
        tree = ast.parse((ROOT / 'iterative_attack_orchestrator/iterative_attack_claude_code.py').read_text())
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name in ('_append_run_log', 'cmd_summary')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / '000.json'
            sample.write_text(json.dumps({'status': 'hit'}))
            cfg = {'log_path': directory, 'target_model': 'offline', 'dataset': 'test', 'max_iters': 10}
            namespace = {'sys': sys, 'json': json, 'Path': Path, 'argparse': SimpleNamespace(Namespace=object),
                         'RESULTS_FILENAME': 'results.json', '_load_run': lambda _: (cfg, []),
                         '_list_samples': lambda _: [sample], '_effective_status': lambda s: s['status']}
            exec(compile(ast.Module(body=nodes, type_ignores=[]), '<summary>', 'exec'), namespace)
            output, error = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                code = namespace['cmd_summary'](SimpleNamespace(run_dir=directory))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())['n_hits'], 1)
            self.assertEqual(json.loads((root / 'results.json').read_text())['summary']['n_hits'], 1)
            self.assertIn('WARNING', error.getvalue())

    @unittest.skipUnless(os.geteuid() == 0, 'root required for training ACL provisioning')
    def test_existing_and_new_nested_logs_inherit_user_acl(self):
        source = (ROOT / 'piminer_train_parallel.sh').read_text()
        block = source.split('# ===== BEGIN:')[1].split('# ===== END:')[0].split('\n', 1)[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.git').mkdir()
            (root / '.git/private').write_text('unchanged')
            (root / '.git/private').chmod(0o600)
            (root / 'logs').mkdir()
            (root / 'logs/old.log').write_text('old')
            (root / 'logs/old.log').chmod(0o600)
            result = subprocess.run(['bash', '-c', 'set -uo pipefail\nDIR=run\n' + block],
                                    cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            (root / 'logs/new').mkdir()
            (root / 'logs/new/new.log').write_text('new')
            for path in (root / 'logs/old.log', root / 'logs/new', root / 'logs/new/new.log'):
                acl = subprocess.check_output(['getfacl', '-cp', str(path)], text=True)
                self.assertIn('user:claudeuser:rwx', acl)
            acl = subprocess.check_output(['getfacl', '-cp', str(root / 'logs/new')], text=True)
            self.assertIn('default:user:claudeuser:rwx', acl)
            self.assertNotIn('user:claudeuser:', subprocess.check_output(
                ['getfacl', '-cp', str(root / '.git/private')], text=True))
            result = subprocess.run(['runuser', '-u', 'claudeuser', '--', 'bash', '-c',
                                     'printf appended >> "$1"; printf appended >> "$2"', 'test',
                                     str(root / 'logs/old.log'), str(root / 'logs/new/new.log')],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'logs/old.log').read_text(), 'oldappended')
            self.assertEqual((root / 'logs/new/new.log').read_text(), 'newappended')

    def test_wrong_working_directory_rejected_before_acl_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = subprocess.check_output(['getfacl', '-cp', directory], text=True)
            result = subprocess.run(['bash', str(ROOT / 'piminer_train_parallel.sh'), 'missing'],
                                    cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('project directory', result.stderr)
            self.assertEqual(subprocess.check_output(['getfacl', '-cp', directory], text=True), original)


if __name__ == '__main__':
    unittest.main()
