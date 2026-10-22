#!/usr/bin/env python3
"""Supplied development feedback only. No evaluator, answer key or model."""
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent


def check():
    if (ROOT/'review.rs').exists():
        try:
            answer = json.loads((ROOT/'review.json').read_text())
            if not isinstance(answer, dict) or set(answer) != {'findings'} or not isinstance(answer['findings'], list):
                return False, 'Expected one findings array.'
            for finding in answer['findings']:
                if (not isinstance(finding, dict) or set(finding) != {'block', 'severity', 'explanation'}
                        or not all(isinstance(finding[k], str) and finding[k].strip() for k in finding)
                        or finding['severity'] != 'high'):
                    return False, 'Each finding needs block, high severity, and a nonempty explanation.'
            return True, 'JSON shape valid; defect accuracy and explanation quality are not checked.'
        except (ValueError, OSError, TypeError):
            return False, 'Create a valid review.json.'
    source = 'feedback-tests.rs' if (ROOT/'feedback-tests.rs').exists() else 'check.rs'
    with tempfile.TemporaryDirectory(prefix='harness-feedback-') as directory:
        binary = Path(directory)/'checks'
        try:
            compiled = subprocess.run(['rustc', '--edition=2021', '--test', str(ROOT/source), '-o', str(binary)],
                                      capture_output=True, text=True, timeout=10)
            if compiled.returncode:
                return False, compiled.stderr[-4000:]
            result = subprocess.run([str(binary), '--test-threads=1'], capture_output=True, text=True, timeout=5)
            count = re.search(r'running (\d+) tests?', result.stdout)
            nonempty = count is not None and int(count[1]) > 0
            return result.returncode == 0 and nonempty, result.stdout[-4000:]+result.stderr[-1000:]
        except (OSError, subprocess.TimeoutExpired) as error:
            return False, type(error).__name__


if __name__ == '__main__':
    passed, message = check()
    print(message)
    raise SystemExit(0 if passed else 1)
