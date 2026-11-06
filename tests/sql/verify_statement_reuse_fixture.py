"""Verify the ordinary SQLite comparison model directly from fixed DEX bytes."""
import argparse,hashlib,importlib.util
from pathlib import Path
if not __debug__:raise SystemExit('fixture verification requires assertions enabled')
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args();root=a.root.resolve()
fixture=root/'tests/fixtures/generated/multisource/raw-a.dex'
spec=importlib.util.spec_from_file_location('reuse_oracle',root/'tools/evidence_verifier/verify.py');oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
parsed=oracle.parse_dex(fixture)
declarations=sorted(parsed['definitions'],key=lambda row:row['declaration_offset'])
assert [(i,row['method_index'],row['name']) for i,row in enumerate(declarations)]==[(0,2,'second'),(1,1,'locate')]
print('PASS independently parsed SQLite materialized comparison fixture',hashlib.sha256(fixture.read_bytes()).hexdigest())
