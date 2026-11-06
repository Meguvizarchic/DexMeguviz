"""Independently check the DEX declaration order used by the provisional SQL oracle."""
import argparse,hashlib,importlib.util,json
from pathlib import Path
if not __debug__:raise SystemExit('fixture oracle requires assertions enabled')
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
root=a.root.resolve();out=a.out.resolve();fixture=root/'tests/fixtures/generated/method_facts/method-uses.dex';oracle=root/'tools/evidence_verifier/verify.py';test=root/'tests/sql/failure_and_cursor/provisional_tests.cpp'
if out.exists():raise SystemExit('output exists')
sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest();inputs=[Path(__file__).resolve(),fixture,oracle,test];before={str(x):sha(x) for x in inputs}
if sha(fixture)!='8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc':raise SystemExit('fixture identity mismatch')
spec=importlib.util.spec_from_file_location('raw_dex_oracle',oracle);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
parsed=module.parse_dex(fixture);by_declaration=sorted(parsed['definitions'],key=lambda x:x['declaration_offset'])
expected=['nativeMethod','quiet','uses','abstractMethod'];assert [x['name'] for x in by_declaration]==expected
assert [x['kind'] for x in by_declaration]==['direct','direct','direct','virtual']
assert all(name in test.read_text(encoding='utf-8') for name in expected)
after={str(x):sha(x) for x in inputs};assert before==after
out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps({'outcome':'passed','scope':'one raw DEX class_data declaration order; independent Python byte parser, not ART','source_sha256':sha(fixture),'declaration_order':expected,'inputs_before':before,'inputs_after':after},indent=2)+'\n',encoding='utf-8');print('PASS provisional SQL reference fixture order')
