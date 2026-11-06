"""Real CLI publication checks, including failure and protected-path cases."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

if not __debug__:
    raise SystemExit('test requires assertions enabled')
parser = argparse.ArgumentParser()
for name in ('tool', 'exe', 'root', 'out'):
    parser.add_argument('--' + name, type=Path, required=True)
args = parser.parse_args()
tool, exe, root, out = (getattr(args, n).resolve() for n in ('tool', 'exe', 'root', 'out'))
if out.exists():
    raise SystemExit('output exists')
original_fixture = root / 'tests/fixtures/generated/graph/amb-a.dex'
inputs = [tool, exe, original_fixture, Path(__file__).resolve(), Path(sys.executable).resolve()]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
before = {str(p): sha(p) for p in inputs}
out.mkdir(parents=True)
fixture = out / 'input.dex'
fixture.write_bytes(original_fixture.read_bytes())
assert sha(fixture) == sha(original_fixture)
inputs.append(fixture)
before[str(fixture)] = sha(fixture)
records = []

def run(name, *extra, ok=True):
    command = [sys.executable, '-B', str(tool), '--exe', str(exe), '--before', str(fixture),
               '--after', str(fixture), *map(str, extra)]
    result = subprocess.run(command, capture_output=True, timeout=300)
    (out / (name + '.stdout')).write_bytes(result.stdout)
    (out / (name + '.stderr')).write_bytes(result.stderr)
    records.append({'name': name, 'exit_code': result.returncode,
                    'stdout_sha256': hashlib.sha256(result.stdout).hexdigest()})
    assert (result.returncode == 0) == ok, (name, result.returncode, result.stderr)
    return result

ordinary = run('stdout')
assert json.loads(ordinary.stdout)['schema_version'] == 1
dest = out / 'result.json'
dest.write_bytes(b'previous result')
published = run('publish', '--output', dest)
assert not published.stdout and dest.read_bytes() == ordinary.stdout
sentinel = b'previous result retained on failure'
dest.write_bytes(sentinel)
failed = run('budget-failure', '--max-results', '1', '--output', dest, ok=False)
assert not failed.stdout and b'BudgetExceeded' in failed.stderr and dest.read_bytes() == sentinel
missing = out / 'missing.json'
run('failure-no-new-file', '--max-results', '1', '--output', missing, ok=False)
assert not missing.exists()
for name, target in [('input-alias', fixture), ('exe-alias', exe), ('script-alias', tool)]:
    rejected = run(name, '--output', target, ok=False)
    assert not rejected.stdout and b'aliases an input or executable' in rejected.stderr
hardlink = out / 'fixture-hardlink.dex'
os.link(fixture, hardlink)
rejected = run('hardlink-alias', '--output', hardlink, ok=False)
assert not rejected.stdout and b'aliases an input or executable' in rejected.stderr
symlink = out / 'fixture-symlink.dex'
try:
    os.symlink(fixture, symlink)
except (OSError, NotImplementedError):
    symlink_check = 'unavailable'
else:
    rejected = run('symlink-alias', '--output', symlink, ok=False)
    assert not rejected.stdout and b'not a link' in rejected.stderr
    symlink_check = 'passed'
spec = importlib.util.spec_from_file_location('diff_under_test', tool)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
old_replace = module.os.replace
def fail_replace(*unused):
    raise OSError('injected replace failure')
module.os.replace = fail_replace
try:
    try:
        module.publish_output(dest, b'new result', {fixture, exe, tool})
        raise AssertionError('injected failure accepted')
    except OSError as error:
        assert str(error) == 'injected replace failure'
finally:
    module.os.replace = old_replace
assert dest.read_bytes() == sentinel and not list(out.glob('.result.json.*.tmp'))
after = {str(p): sha(p) for p in inputs}
assert before == after
(out / 'summary.json').write_text(json.dumps({'outcome': 'passed', 'scope': 'Windows host fixed CLI inputs, no concurrent writer or crash durability proof',
    'inputs_before': before, 'inputs_after': after, 'records': records, 'replace_failure': 'injected',
    'symlink_check': symlink_check}, indent=2) + '\n', encoding='utf-8')
print('PASS atomic CI output, failures and protected aliases')
