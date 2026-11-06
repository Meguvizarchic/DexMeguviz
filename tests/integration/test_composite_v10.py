"""Composite evidence against authored source bytes, independent of runtime binding."""
import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--exe', required=True, type=Path)
parser.add_argument('--root', required=True, type=Path)
args = parser.parse_args()
fixture = args.root / 'tests/fixtures/generated/composite-v10/composite.dex'
root = args.root / 'tests/fixtures/generated/inherited/root.dex'
raw = fixture.read_bytes()
assert hashlib.sha256(raw).hexdigest() == 'ae071f078b042f7455c69c7044bed82209faff9bdb5c807bd9088da458ac3d63'
assert raw[12:32] == hashlib.sha1(raw[32:]).digest()
assert struct.unpack_from('<I', raw, 8)[0] == zlib.adler32(raw[12:]) & 0xffffffff
assert struct.unpack_from('<9H', raw, 460) == (0x71, 0, 0, 0x13, 0xffff, 0, 0, 0, 0x0e)
generator = args.root / 'tests/fixtures/generators/composite_v10.py'
numeric = {'numeric_bits': {'width': 32, 'bits': 'ffffffff', 'kind': 'constant'}}


def inherited(scope):
    return {'declares_fields': {'scope': scope, 'where': {'name': 'parentOnly'}, 'min': 1}}


def method(scope, include_numeric=True):
    conditions = [{'name': 'access'}, inherited(scope)]
    if include_numeric:
        conditions.append(numeric)
    return {'op': 'scan', 'relation': 'method_defs', 'where': {'all': conditions}}


with tempfile.TemporaryDirectory(prefix='dmg-composite-v10-') as temp:
    temp = Path(temp)
    rebuilt = temp / 'rebuilt'
    subprocess.run([sys.executable, str(generator), '--output', str(rebuilt)], check=True, timeout=30)
    assert (rebuilt / 'composite.dex').read_bytes() == raw

    def run(name, relation, *, capabilities=(), sources=(fixture, root), code=0, **extra):
        query = {'schema_version': 1, 'relation': relation, 'intent': 'unique'}
        if capabilities:
            query['required_capabilities'] = list(capabilities)
        query.update(extra)
        path = temp / (name + '.json')
        path.write_text(json.dumps(query), encoding='utf-8')
        command = [str(args.exe), 'query', str(sources[0])]
        for source in sources[1:]:
            command += ['--source', str(source)]
        result = subprocess.run(command + ['--query', str(path), '--json'], capture_output=True,
                                text=True, encoding='utf-8', timeout=30)
        assert result.returncode == code, (name, result.returncode, result.stdout, result.stderr)
        return json.loads(result.stdout)

    def positive(result, scope, numeric_expected, use_expected):
        assert result['profile'] == 'dex-query-composite-v10' and result['query_id'].startswith('query:v10:')
        assert result['query']['required_capabilities'] & 262144
        assert result['coverage'] == 'Complete' and result['decision'] == 'ProvenTrue'
        assert len(result['candidates']) == 1
        row = result['candidates'][0]
        assert row['source_index'] == 0 and row['name'] == 'access'
        evidence = row['evidence']
        inherited_kind = 'inherited' if scope == 'inherited' else 'interface_inherited'
        assert any(x['kind'] == inherited_kind for x in evidence)
        numeric_items = [x for x in evidence if x['kind'] == 'numeric_literal']
        assert bool(numeric_items) == numeric_expected
        if numeric_expected:
            assert len(numeric_items) == 1
            item = numeric_items[0]
            assert (item['dex_pc'], item['opcode'], item['width_bits'], item['bits']) == (3, 0x13, 32, 'ffffffff')
            assert item['entity']['source_index'] == 0 and item['entity']['relation'] == 'method_defs'
        invokes = [x for x in evidence if x['kind'] == 'invoke']
        assert bool(invokes) == use_expected
        if use_expected:
            assert any(x['dex_pc'] == 0 and x['opcode'] == 0x71 and x['reference_index'] == 0 for x in invokes)
            assert any(link['key'] == 'caller' for link in row['links'])

    ids = []
    for scope in ('inherited', 'inherited_interfaces'):
        direct = run(scope, method(scope))
        positive(direct, scope, True, False)
        ids.append(direct['query_id'])
        for with_numeric in (False, True):
            relation = {'op': 'join', 'on': 'caller', 'left': method(scope, with_numeric),
                        'right': {'op': 'scan', 'relation': 'invoke_sites'}}
            value = run(scope + str(with_numeric), relation, capabilities=('use_streaming',))
            positive(value, scope, with_numeric, True)
            ids.append(value['query_id'])
        uncertain = method(scope)
        uncertain['where']['all'][1]['declares_fields'].update(min=2, max=2)
        missing = run(scope + '-missing', uncertain, sources=(fixture,))
        assert missing['coverage'] == 'Partial' and missing['decision'] == 'Undetermined'
        assert not missing['candidates']
    assert len(set(ids)) == len(ids)

    conflict = {'op': 'scan', 'relation': 'method_defs', 'where': {'all': [inherited('inherited'), inherited('inherited_interfaces')]}}
    run('incompatible-predicates', conflict, code=2)
    run('incompatible-capabilities', method('inherited'), capabilities=('interface_fields', 'composite'), code=2)
    run('unknown-v5', method('inherited'), capabilities=('bounded_expand',), code=2)
    run('no-use-scan', method('inherited'), capabilities=('use_streaming',), code=2)
    limited = run('budget', method('inherited'), code=3, max_work=1)
    assert limited['execution_status'] == 'BudgetExceeded'
    print('PASS composite v10 authored bytes, separate inherited/numeric/use evidence and boundaries')
