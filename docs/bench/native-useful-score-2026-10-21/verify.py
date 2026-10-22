"""External, offline acceptance of the fixed public score fixture, not a generic evaluator.

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
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


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


def run(argv, cwd, env, expected=(0,)):
    result = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=20, preexec_fn=limits)
    require(result.returncode in expected, 'command failed: ' + argv[0])
    require(len(result.stdout) <= 65536, 'command output bound')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
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
    checks = read(HERE/'required-cases.rs', 32768)
    required = re.findall(rb'#\[test\] fn ([a-z_]+)\(', checks)
    require(len(required) == 12 and len(set(required)) == 12, 'required case inventory')
    with tempfile.TemporaryDirectory(prefix='score-acceptance-') as temporary:
        work = Path(temporary)
        env = {'PATH': '/usr/local/cargo/bin:/usr/bin:/bin', 'HOME': temporary,
               'RUSTUP_HOME': '/usr/local/rustup', 'RUSTUP_TOOLCHAIN': '1.85.1',
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
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
        (work/'required-cases.rs').write_bytes(checks)
        outcomes = {}
        for label, data in [('source', source), ('candidate', reconstructed)]:
            (work/'lib.rs').write_bytes(data)
            run(['rustc', '--edition=2021', '--test', 'required-cases.rs', '-o', 'checks'], work, env)
            execution = run([str(work/'checks'), '--test-threads=1'], work, env, expected=(0, 101))
            text = execution.stdout.decode()
            rows = dict(re.findall(r'^test ([a-z_]+) \.\.\. (ok|FAILED)$', text, re.M))
            require(set(rows) == {n.decode() for n in required}, 'missing or extra case')
            outcomes[label] = {'exit_code': execution.returncode, 'cases': rows, 'stdout_sha256': digest(execution.stdout)}
        require(outcomes['source']['exit_code'] == 101, 'negative control did not fail')
        require(outcomes['candidate']['exit_code'] == 0 and all(v == 'ok' for v in outcomes['candidate']['cases'].values()), 'candidate failed required case')
    receipt.update({'schema_version': 1, 'verdict': 'pass_public_score_fixture', 'runtime_report_sha256': digest(raw_report),
                    'required_cases_sha256': digest(checks), 'verifier_sha256': digest(Path(__file__).read_bytes()),
                    'source_tree': source_tree, 'result_tree': result_tree, 'git_mode': '100644', 'outcomes': outcomes,
                    'memory_bytes': 8589934592, 'swap_bytes': 0, 'human_acceptance': None,
                    'independent_author_review': False, 'frozen_hidden_oracle_executed': False,
                    'source_publication': False, 'runtime_verdict_modified': False, 'model_calls_started': 0})
    with args.output.open('x') as output:
        json.dump(receipt, output, indent=2)
        output.write('\n')
    print(json.dumps({'verdict': receipt['verdict'], 'required_cases': len(required), 'result_tree': result_tree}))


if __name__ == '__main__':
    main()
