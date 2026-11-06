"""Compare Kotlin queries with independent expected predicates and exact rows."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
for name in ('exe', 'fixture', 'lines'):
    parser.add_argument('--' + name, required=True, type=Path)
args = parser.parse_args()
queries = {}
for line in args.lines.read_text(encoding='utf-8').splitlines():
    label, payload = line.split('\t', 1)
    assert label not in queries
    queries[label] = json.loads(payload)

first, final = 'Lflags/Ordinary;', 'Lflags/Final;'
constructor = (first, '<init>')
clinit = (first, '<clinit>')
alpha, beta = (first, 'alpha'), (final, 'beta')
all_rows = {constructor, clinit, alpha, beta}
cases = {
    'constructor': ({'kind': 'constructor'}, {constructor}),
    'clinit': ({'kind': 'clinit'}, {clinit}),
    'normal': ({'kind': 'normal'}, {alpha, beta}),
    'owner-exact-public': ({'owner_flags': {'domain': 'dex', 'mode': 'exact', 'value': 1}}, {constructor, clinit, alpha}),
    'owner-exact-final': ({'owner_flags': {'domain': 'dex', 'mode': 'exact', 'value': 17}}, {beta}),
    'owner-exact-absent': ({'owner_flags': {'domain': 'dex', 'mode': 'exact', 'value': 0}}, set()),
    'owner-any-final': ({'owner_flags': {'domain': 'dex', 'mode': 'any', 'value': 16}}, {beta}),
    'owner-any-absent': ({'owner_flags': {'domain': 'dex', 'mode': 'any', 'value': 32}}, set()),
    'owner-any-zero': ({'owner_flags': {'domain': 'dex', 'mode': 'any', 'value': 0}}, set()),
    'owner-contains-zero': ({'owner_flags': {'domain': 'dex', 'mode': 'contains', 'value': 0}}, all_rows),
}
assert set(cases) == set(queries)
with tempfile.TemporaryDirectory(prefix='dmg-kotlin-kind-') as tmp:
    def execute(label, document):
        path = Path(tmp) / (label + '.json')
        path.write_text(json.dumps(document), encoding='utf-8')
        result = subprocess.run([str(args.exe.resolve()), 'query', str(args.fixture.resolve()),
                                 '--query', str(path), '--json'], capture_output=True,
                                text=True, encoding='utf-8', timeout=30)
        assert result.returncode == 0, (label, result.returncode, result.stdout, result.stderr)
        return json.loads(result.stdout)
    for label, (where, rows) in cases.items():
        expected_query = {'schema_version': 1, 'relation': 'method_defs', 'where': where,
                          'intent': 'enumerate', 'max_results': 4096, 'max_work': 100000000}
        actual = execute(label + '-kotlin', queries[label])
        control = execute(label + '-control', expected_query)
        assert actual['profile'] == 'dex-query-method-v1'
        for field in ('query_id', 'coverage', 'decision', 'reason', 'execution_status'):
            assert actual[field] == control[field], (label, field)
        actual_rows = [(item['owner'], item['name']) for item in actual['candidates']]
        assert len(actual_rows) == len(rows) and set(actual_rows) == rows, (label, actual_rows)
        assert [(item['owner'], item['name']) for item in control['candidates']] == actual_rows
print('PASS 10 Kotlin method-kind and owner-flags positive/negative CLI comparisons')
