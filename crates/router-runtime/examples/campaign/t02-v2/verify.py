"""Version 2 finite t02 evaluator. Fixed reviewed inputs only; no adoption authority.

Run inside the qualified disposable Linux cell. This never publishes a source
revision or changes Runtime's objective, validation or human-acceptance state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import signal
import time
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
COMPILER = "/usr/local/rustup/toolchains/1.85.1-aarch64-unknown-linux-gnu/bin/rustc"
VERSION = "t02-score-v2"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read(path, bound):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_size <= bound, 'input shape or size')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(bound + 1)
        require(len(data) == meta.st_size, 'changed input')
        return data
    finally:
        os.close(fd)


def verify_bindings(packet, report, source, candidate, patch):
    require(report['schema_version'] == 1, 'report version')
    require(report.get('human_acceptance') is None, 'unexpected human acceptance')
    for key in ('assignment_id', 'packet_sha256'):
        require(report[key] == packet[key], key)
    require(source == packet['files']['lib.rs'].encode(), 'source preimage')
    require(candidate != source, 'no correction')
    require(report['source_unchanged'] is True, 'source changed')
    require(report['runtime_failed'] is False and report['export_failed'] is False, 'failed run/export')
    require(report['cleanup'] == 'namespace_terminated', 'unknown cleanup')
    require(report['admission']['granted'] == 0 and report['admission']['released'] == 1, 'retained admission')
    result = report['result']
    require(result['run']['run_id'] == packet['assignment_id'], 'run identity')
    require(result['memory_enforcement'] == 'enforced', 'memory enforcement')
    require(result['run']['state'] == 'verifying', 'unexpected run state')
    require(result['transport']['exit_code'] == 0 and result['transport']['termination'] == 'exited', 'transport failed')
    require(report['submission'] == {'relative': 'lib.rs', 'bytes': len(candidate), 'sha256': digest(candidate)}, 'export binding')
    require(result['run']['artifact_sha256'] == digest(patch), 'patch binding')
    return {'packet_sha256': packet['packet_sha256'], 'frozen_campaign_acceptance_sha256': packet['acceptance_sha256'],
            'source_sha256': digest(source), 'candidate_sha256': digest(candidate), 'artifact_sha256': digest(patch)}


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (8589934592, 8589934592))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16777216, 16777216))


class InfrastructureFailure(Exception):
    """No functional conclusion can be drawn from an unavailable execution."""


def run(argv, cwd, env, expected=(0,), timeout=20):
    # Disk-backed output is bounded before capture. Keep the leader waitable
    # until its group has been killed, including on success.
    with tempfile.TemporaryFile(dir=cwd) as capture:
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=capture,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     start_new_session=True, preexec_fn=limits)
        except (OSError, subprocess.SubprocessError) as error:
            raise InfrastructureFailure('spawn_failed') from error
        deadline = time.monotonic() + timeout
        timed_out = False
        try:
            while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                time.sleep(0.01)
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
        capture.seek(0)
        output = capture.read(65537)
        if timed_out:
            raise InfrastructureFailure('timeout')
        if len(output) > 65536:
            raise InfrastructureFailure('output_limit')
        if child.returncode not in expected:
            raise InfrastructureFailure('unexpected_exit')
        return subprocess.CompletedProcess(argv, child.returncode, output)


def classify(returncode, output, required):
    unknown = {'outcome': 'unknown', 'cases': {name: 'unknown' for name in required}}
    if len(output) > 65536 or not required or len(set(required)) != len(required):
        return unknown
    text = output.decode('utf-8', errors='replace')
    rows = re.findall(r'^test ([a-z0-9_]+) \.\.\. (ok|FAILED)$', text, re.M)
    summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [^\r\n]+$', text, re.M)
    if len(rows) != len(required) or set(name for name, _ in rows) != set(required) or len(summaries) != 1:
        return unknown
    status, *counts = summaries[0]
    passed, failed, ignored, measured, filtered = map(int, counts)
    if ignored or measured or filtered or passed != sum(value == 'ok' for _, value in rows) or failed != sum(value == 'FAILED' for _, value in rows):
        return unknown
    if (returncode, status, failed) == (0, 'ok', 0):
        outcome = 'passed'
    elif returncode == 101 and status == 'FAILED' and failed > 0:
        outcome = 'failed'
    else:
        return unknown
    return {'outcome': outcome, 'cases': dict(rows)}


def environment(work):
    return {'PATH': '/usr/bin:/bin', 'HOME': str(work), 'LANG': 'C', 'LC_ALL': 'C',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}


def evaluate_source(source, checks, required, work, compiler=COMPILER):
    (work / 'lib.rs').write_bytes(source)
    (work / 'required-cases.rs').write_bytes(checks)
    stage = 'compile'
    try:
        run([compiler, '--edition=2021', '--test', 'required-cases.rs', '-o', 'checks'], work, environment(work))
        stage = 'test'
        execution = run([str(work / 'checks'), '--test-threads=1'], work, environment(work), expected=(0, 101))
    except InfrastructureFailure as error:
        return {'outcome': 'unknown', 'stage': stage, 'reason': str(error),
                'cases': {name: 'unknown' for name in required}}
    row = classify(execution.returncode, execution.stdout, required)
    row.update({'stage': stage, 'exit_code': execution.returncode, 'stdout_sha256': digest(execution.stdout)})
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    require(Path('/sys/fs/cgroup/memory.max').read_text().strip() == '8589934592', '8 GiB cgroup required')
    require(Path('/sys/fs/cgroup/memory.swap.max').read_text().strip() == '0', 'zero swap required')
    packets = json.loads(read(ROOT/'crates/router-runtime/examples/campaign/packets.json', 1048576))['assignments']
    packet = next(p for p in packets if p['assignment_id'] == 't02-Lm-r1-H1')
    source, candidate, patch = [read(args.input/n, 65536) for n in ('source-lib.rs', 'lib.rs', 'change.patch')]
    raw_report = read(args.input/'runtime-result.json', 4194304)
    report = json.loads(raw_report)
    receipt = verify_bindings(packet, report, source, candidate, patch)
    # This fixture runner executes only the already published authored solution.
    # It is not authority to compile arbitrary untrusted candidate bytes.
    authored = json.loads(read(ROOT/'docs/bench/linux-finite-dispatch-2026-10-16/inputs/t02/controller/control-output.json', 65536))['lib.rs'].encode()
    require(candidate == authored, 'unreviewed fixture candidate')
    checks = read(HERE/'cases.rs', 32768)
    required = re.findall(rb'fn (t02_v2_[a-z0-9_]+)\(', checks)
    require(len(required) == 18 and len(set(required)) == 18, 'required case inventory')
    required = [name.decode() for name in required]
    with tempfile.TemporaryDirectory(prefix='score-acceptance-') as temporary:
        work = Path(temporary)
        env = environment(work)
        run(['git', 'init', '-q'], work, env)
        (work/'lib.rs').write_bytes(source)
        run(['git', 'add', '--', 'lib.rs'], work, env)
        source_tree = run(['git', 'write-tree'], work, env).stdout.decode().strip()
        (work/'change.patch').write_bytes(patch)
        run(['git', 'apply', '--cached', '--check', 'change.patch'], work, env)
        run(['git', 'apply', '--cached', 'change.patch'], work, env)
        entries = run(['git', 'ls-files', '--stage'], work, env).stdout.decode().splitlines()
        require(len(entries) == 1 and entries[0].startswith('100644 ') and entries[0].endswith('\tlib.rs'), 'changed scope or mode')
        reconstructed = run(['git', 'show', ':lib.rs'], work, env).stdout
        require(reconstructed == candidate, 'patch does not reconstruct export')
        result_tree = run(['git', 'write-tree'], work, env).stdout.decode().strip()
        canonical_patch = run(['git', 'diff', '--cached', '--no-ext-diff', '--no-color', source_tree, '--'], work, env).stdout
        require(canonical_patch == patch, 'noncanonical or replaced displayed diff')
        outcomes = {label: evaluate_source(data, checks, required, work)
                    for label, data in [('source', source), ('candidate', reconstructed)]}
        require(outcomes['source']['outcome'] == 'failed', 'negative control inconclusive')
        require(outcomes['candidate']['outcome'] == 'passed', 'candidate evaluation inconclusive or failed')
        compiler_version = run([COMPILER, '--version', '--verbose'], work, env).stdout.decode().strip()
    receipt.update({'evaluator_id': VERSION, 'compiler_version': compiler_version,
                    'compiler_sha256': digest(read(Path(COMPILER), 67108864)),
                    'predecessor_oracle_sha256': 'dcf8247d51256f888681b604b29503304eaa7fca89a9be97c3c6f1373c92b821',
                    'oracle_authenticity': 'supplied_unverified', 'adoption_authorized': False,
                    'case_role': 'qualification',
                    'decision_cases_executed': False})
    receipt.update({'schema_version': 2, 'verdict': 'pass_t02_v2_qualification_fixture', 'runtime_report_sha256': digest(raw_report),
                    'required_cases_sha256': digest(checks), 'verifier_sha256': digest(Path(__file__).read_bytes()),
                    'source_tree': source_tree, 'result_tree': result_tree, 'git_mode': '100644', 'outcomes': outcomes,
                    'memory_bytes': 8589934592, 'swap_bytes': 0, 'human_acceptance': None,
                    'independent_author_review': False, 'frozen_hidden_oracle_executed': False,
                    'source_publication': False, 'runtime_verdict_modified': False, 'model_calls_started': 0})
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(receipt, output, indent=2)
        output.write('\n')
    print(json.dumps({'verdict': receipt['verdict'], 'required_cases': len(required), 'result_tree': result_tree}))


if __name__ == '__main__':
    main()
