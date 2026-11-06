"""Check the bounded S10 fixture directly; no native scanner is consulted."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,struct
if not __debug__: raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);root=p.parse_args().root
fixture=root/'tests/fixtures/generated/method_facts/method-uses.dex';reader=root/'tools/evidence_verifier/verify.py';data=fixture.read_bytes();digest=hashlib.sha256(data).hexdigest()
assert digest=='8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc'
spec=importlib.util.spec_from_file_location('raw_metadata',reader);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);parsed=mod.parse_dex(data)
def body(name):
 definition=next(x for x in parsed['definitions'] if x['name']==name);offset=definition['code_offset'];count=struct.unpack_from('<I',data,offset+12)[0];return list(struct.unpack_from('<'+str(count)+'H',data,offset+16))
assert body('quiet')==[0x000e]
strings=parsed['strings'];sink=next(x['method_index'] for x in parsed['references'] if x['name']=='sink')
assert body('uses')==[0x001a,strings.index('used-string'),0x0071,sink,0,0x0060,0,0x000e]
assert all(x['code_offset']==0 for x in parsed['definitions'] if x['name'] in ('nativeMethod','abstractMethod'))
print(json.dumps({'status':'passed','fixture_sha256':digest,'per_occurrence':{'string_uses':1,'invoke_sites':1,'invoke_dex_pc':2},'scope':'exact independently parsed fixture code units; not a general DEX decoder or runtime evidence'}))
