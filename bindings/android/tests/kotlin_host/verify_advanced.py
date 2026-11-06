"""Independent JSON-depth/UTF-16 and core QueryID checks for Kotlin fallbacks."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--exe', required=True, type=Path)
parser.add_argument('--fixture', required=True, type=Path)
parser.add_argument('--lines', required=True, type=Path)
parser.add_argument('--legacy-lines', required=True, type=Path)
args = parser.parse_args()
generated = {}
for line in args.lines.read_text(encoding='utf-8').splitlines():
    name, raw = line.split('\t', 1)
    assert name not in generated
    generated[name] = (raw, json.loads(raw))

def text(value):
    return {'name': {'op': 'exact', 'value': value, 'ascii_case_insensitive': False}}

def null_array(count):
    return {'name': {'op': 'exact', 'u16': [0] * count, 'ascii_case_insensitive': False}}

def negated(value, count):
    for _ in range(count): value = {'not': value}
    return value

unicode_text = 'x' * 16400 + '\0"\\' + chr(0xd800) + 'Q' + chr(0xdfff) + chr(0xd83d) + chr(0xde00) + chr(0x7f)
expected = {
    'old-comparable': text('x' * 10000),
    'long-ascii': text('x' * 20000),
    'long-backspace': text('\b' * 16400),
    'long-escaped': text(unicode_text),
    'combined': {'all': [text('x' * 9000), text('x' * 9000)]},
    'depth-limit': negated(True, 31),
    'text-depth-fallback': negated(text('x'), 29),
    'null-node-boundary': null_array(16373),
    'mixed-auto': {'all': [text('\0' * 6000), null_array(6000), null_array(6000)]},
    'mixed-explicit': {'all': [text('\0' * 6000), null_array(6000), null_array(6000)]},
    'greedy-explicit': {'all': [null_array(15000), null_array(1000), text('\u0080' * 3000), text('z' * 13500)]},
    'outer-mixed': {'all': [{'name': {'op':'exact', 'u16':[65535]*10404, 'ascii_case_insensitive':False}}, text('x'*400), null_array(600)]},
    'outer-explicit': {'all': [{'name': {'op':'exact', 'u16':[65535]*10404, 'ascii_case_insensitive':False}}, text('x'*400), null_array(600)]},
}
expected['outer-mixed-wide'] = expected['outer-mixed']
assert set(generated) == set(expected) | {'null-node-over', 'greedy-incomplete'}

def bounds(value, depth=0):
    nodes = 1
    maximum = depth
    if isinstance(value, dict): children = value.values()
    elif isinstance(value, list): children = value
    else: children = ()
    for child in children:
        child_nodes, child_depth = bounds(child, depth + 1)
        nodes += child_nodes; maximum = max(maximum, child_depth)
    return nodes, maximum

assert '"u16":[' in generated['old-comparable'][0]
for name in ('long-ascii', 'long-backspace', 'long-escaped', 'combined', 'text-depth-fallback'):
    assert '"value":' in generated[name][0]
assert '\\b' * 16400 in generated['long-backspace'][0]
assert '\\u0000' in generated['long-escaped'][0] and '\\ud800' in generated['long-escaped'][0] and '\\udfff' in generated['long-escaped'][0]
assert bounds(generated['depth-limit'][1])[1] == 32
assert bounds(generated['text-depth-fallback'][1])[1] == 32
assert bounds(generated['null-node-boundary'][1])[0] == 16384
assert bounds(generated['null-node-over'][1])[0] == 16385
def array_fragment(value):
    return '{"name":{"op":"exact","u16":[' + ','.join(str(ord(c)) for c in value) + '],"ascii_case_insensitive":false}}'
def value_fragment(value):
    return '{"name":{"op":"exact","value":' + json.dumps(value, ensure_ascii=True) + ',"ascii_case_insensitive":false}}'
outer_values = ('\uffff'*10404, 'x'*400, '\0'*600)
outer_prefix = '{"schema_version":1,"relation":"method_defs","where":'
outer_suffix = ',"intent":"enumerate","max_results":4096,"max_work":100000000}'
fragment = lambda parts: '{"all":[' + ', '.join(parts) + ']}'
primary = fragment([array_fragment(v) for v in outer_values])
all_alternative = fragment([value_fragment(v) for v in outer_values])
outer_capacity = 65536 - len(outer_prefix) - len(outer_suffix)
assert len(primary) <= 65536 and len(primary) > outer_capacity
assert len(all_alternative) > 65536
assert len(generated['outer-mixed'][0]) <= 65536
for name in ('mixed-auto', 'mixed-explicit'):
    assert generated[name][0].count('"value":') == 1 and generated[name][0].count('"u16":') == 2

with tempfile.TemporaryDirectory(prefix='dmg-kotlin-advanced-') as temporary:
    temp = Path(temporary)
    def run(name, payload):
        path = temp/(name+'.json')
        path.write_bytes(payload)
        result = subprocess.run([str(args.exe.resolve()), 'query', str(args.fixture.resolve()), '--query', str(path), '--json'],
                                capture_output=True, text=True, encoding='utf-8', timeout=60)
        assert result.returncode == 0, (name, result.returncode, result.stdout, result.stderr)
        return json.loads(result.stdout)
    for name, where in expected.items():
        raw, doc = generated[name]
        assert len(raw.encode('ascii')) <= 65536
        nodes, depth = bounds(doc)
        assert nodes <= 16384 and depth <= 32, (name, nodes, depth)
        control = {'schema_version':1,'relation':'method_defs','where':where,'intent':'enumerate',
                   'max_results':4096,'max_work':9223372036854775807 if name == 'outer-mixed-wide' else 100000000}
        kotlin = run(name+'-kotlin', raw.encode('ascii'))
        manual = run(name+'-manual', json.dumps(control, ensure_ascii=True, separators=(',',':')).encode('ascii'))
        for key in ('query_id','execution_status','coverage','decision','reason'):
            assert kotlin[key] == manual[key], (name, key, kotlin[key], manual[key])
        assert kotlin['candidates'] == manual['candidates'], name
    assert generated['outer-mixed'][0] == generated['outer-explicit'][0]
    assert generated['outer-mixed'][0].count('"value":') == 1
    assert generated['outer-mixed'][0].count('"u16":') == 2
    path = temp/'null-node-over.json'; path.write_bytes(generated['null-node-over'][0].encode('ascii'))
    over = subprocess.run([str(args.exe.resolve()), 'query', str(args.fixture.resolve()), '--query', str(path), '--json'],
                          capture_output=True, text=True, encoding='utf-8', timeout=60)
    assert over.returncode == 2 and json.loads(over.stdout)['execution_status'] == 'InvalidArgument'
    raw, document = generated['greedy-incomplete']
    assert len(raw.encode('ascii')) <= 65536 and bounds(document)[0] > 16384
    path = temp/'greedy-incomplete.json'; path.write_bytes(raw.encode('ascii'))
    incomplete = subprocess.run([str(args.exe.resolve()), 'query', str(args.fixture.resolve()), '--query', str(path), '--json'],
                                capture_output=True, text=True, encoding='utf-8', timeout=60)
    assert incomplete.returncode == 2 and json.loads(incomplete.stdout)['execution_status'] == 'InvalidArgument'
    legacy = dict(line.split('\t', 1) for line in args.legacy_lines.read_text(encoding='utf-8').splitlines())
    old = run('legacy-surrogate-u16', legacy['unicode'].encode('ascii'))
    legacy_control = {'schema_version':1,'relation':'method_defs','where':text('A\0'+chr(0xd800)+'X'+chr(0xdfff)),
                      'intent':'unique','max_results':4096,'max_work':100000000}
    alternate = run('legacy-surrogate-value', json.dumps(legacy_control, ensure_ascii=True, separators=(',',':')).encode('ascii'))
    for key in ('query_id','execution_status','coverage','decision','reason','candidates'):
        assert old[key] == alternate[key], ('legacy-surrogate', key)
print('PASS 14 bounded encodings, legacy surrogate QueryID, node boundary and explicit greedy recovery')
