"""Bounded raw code-item fingerprints against independent fixed byte evidence."""
import argparse, hashlib, importlib.util, json, struct, subprocess, sys, zipfile, zlib
from pathlib import Path
if not __debug__: raise SystemExit('test requires assertions enabled')
p=argparse.ArgumentParser()
for name in ('tool','exe','root','out'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();root=a.root.resolve();tool=a.tool.resolve();exe=a.exe.resolve();out=a.out.resolve()
if out.exists():raise SystemExit('output exists')
B=root/'tests/fixtures/generated/graph/amb-b1.dex';shared=root/'tests/fixtures/generated/extended/shared-items.dex';oracle=root/'tests/integration/raw_graph_oracle.py'
catalog=root/'tests/fixtures/generated/definition_catalog/definitions.dex'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
inputs=[Path(__file__).resolve(),Path(sys.executable).resolve(),tool,exe,B,shared,catalog,oracle];before={str(x):sha(x) for x in inputs}
spec=importlib.util.spec_from_file_location('raw_oracle',oracle);raw=importlib.util.module_from_spec(spec);spec.loader.exec_module(raw)
parsed=raw.parse(B);assert parsed['code_offset']==260 and tuple(parsed['definition'])==('Lamb/B;','b','()V')
out.mkdir(parents=True);records=[]
def run(name,args,ok=True):
 r=subprocess.run([sys.executable,'-B',str(tool),'--exe',str(exe),*map(str,args)],capture_output=True,timeout=300)
 (out/(name+'.stdout.json')).write_bytes(r.stdout);(out/(name+'.stderr.log')).write_bytes(r.stderr)
 assert (r.returncode==0)==ok,(name,r.returncode,r.stderr)
 if not ok:assert not r.stdout,(name,'partial output')
 records.append({'name':name,'exit_code':r.returncode,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest()})
 return json.loads(r.stdout) if ok else r

def method(result):
 rows=[x for x in result['symbols'] if x['symbol']==['method','Lamb/B;','b','()V']]
 assert len(rows)==1;return rows[0]
# The DEX method-id table is unchanged; only the valid invoke target index changes.
changed=bytearray(B.read_bytes()); at=parsed['code_offset']
assert struct.unpack_from('<4H',changed,at+16)==(0x71,1,0,0x0e)
struct.pack_into('<H',changed,at+18,0)
changed[12:32]=hashlib.sha1(changed[32:]).digest();struct.pack_into('<I',changed,8,zlib.adler32(changed[12:])&0xffffffff)
modified=out/'code-changed.dex';modified.write_bytes(changed)
base=run('default-unchanged-format',['--before',B,'--after',modified,'--before-complete','--after-complete'])
row=method(base);assert 'code_fingerprint' not in base and 'code_changed' not in row and 'code_sha256' not in row['before']['definitions'][0]
result=run('code-change',['--before',B,'--after',modified,'--before-complete','--after-complete','--code-digest'])
row=method(result);assert not row['count_changed'] and not row['attributes_changed'] and row['code_changed']
assert result['code_fingerprint']['format']=='raw-code-item-v1'
orig=B.read_bytes(); end=at+16+struct.unpack_from('<I',orig,at+12)[0]*2
expected='sha256:raw-code-item:v1:'+hashlib.sha256(b'DexMeguviz:raw-code-item:v1\0'+orig[at:at+8]+bytes(4)+orig[at+12:end]).hexdigest()
assert row['before']['definitions'][0]['code_sha256']==expected and row['after']['definitions'][0]['code_sha256']!=expected
# A known abstract definition has no code item and remains null, not an empty digest.
assert sha(catalog)=='e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a'
empty=run('no-body',['--before',catalog,'--after',catalog,'--code-digest'])
abstract=[x for x in empty['symbols'] if x['symbol']==['method','Lcatalog/Child;','abstractMethod','()V']]
assert len(abstract)==1 and not abstract[0]['code_changed'] and abstract[0]['before']['definitions'][0]['code_sha256'] is None
# Same DEX in stored and deflated APKs must yield the same code bytes.
for compression,label in ((zipfile.ZIP_STORED,'stored'),(zipfile.ZIP_DEFLATED,'deflated')):
 path=out/(label+'.apk')
 info=zipfile.ZipInfo('classes.dex',(1980,1,1,0,0,0));info.compress_type=compression;info.create_system=0;info.external_attr=0
 with zipfile.ZipFile(path,'w') as z:z.writestr(info,orig)
 result=run('archive-'+label,['--before',B,'--after',path,'--code-digest'])
 row=method(result);assert not row['code_changed'] and row['after']['definitions'][0]['code_sha256']==expected
 assert result['after']['sources'][0]['archive_entry_name']=='classes.dex'
# An independently known code_item includes tries plus an encoded catch list.
spec=importlib.util.spec_from_file_location('codediff',tool);diff=importlib.util.module_from_spec(spec);spec.loader.exec_module(diff)
s=shared.read_bytes();offset=656; end=689
assert sha(shared)=='135c62685a5265e10388353873bbd41d18ffd0ac871329d42eb46eefd9f34734'
assert struct.unpack_from('<HHHHII',s,offset)==(1,0,0,1,0,2)
expected_try='sha256:raw-code-item:v1:'+hashlib.sha256(b'DexMeguviz:raw-code-item:v1\0'+s[offset:offset+8]+bytes(4)+s[offset+12:end]).hexdigest()
assert diff._code_item_digest(s,offset,[100])==expected_try
relocated=bytearray(s);struct.pack_into('<I',relocated,offset+8,0x12345678)
assert diff._code_item_digest(relocated,offset,[100])==expected_try
for name,data,work in [('truncated',s[:end-1],[100]),('work-exhausted',s,[1])]:
 try:diff._code_item_digest(data,offset,work)
 except diff.DiffError:pass
 else:raise AssertionError(name+' accepted')
# Malformed LEB values and forged source/entry metadata must not produce a digest.
for payload,signed in ((bytes.fromhex('ff ff ff ff 10'),False),(bytes.fromhex('80 80 80 80 08'),True)):
 try:diff._leb32(payload,0,signed)
 except diff.DiffError:pass
 else:raise AssertionError('overflowing LEB accepted')
raw_source={'source_bytes':len(orig),'source_sha256':'0'*64}
try:diff._read_source_bytes(B,raw_source,{'format':'RawDex'},1024*1024)
except diff.DiffError:pass
else:raise AssertionError('forged DEX digest accepted')
archive=out/'stored.apk';wrong={'source_bytes':len(orig),'source_sha256':sha(B),'archive_entry_index':0,'archive_entry_name':'classes2.dex'}
try:diff._read_source_bytes(archive,wrong,{'format':'Apk'},1024*1024)
except diff.DiffError:pass
else:raise AssertionError('forged archive entry accepted')
# A corrupted deflate stream must become a bounded comparison failure, not leak zlib.error.
corrupt=bytearray((out/'deflated.apk').read_bytes())
with zipfile.ZipFile(out/'deflated.apk') as z:
 info=z.infolist()[0]
 header=struct.unpack_from('<IHHHHHIIIHH',corrupt,info.header_offset)
 assert header[0]==0x04034b50
 position=info.header_offset+30+header[-2]+header[-1]
assert corrupt[position]!=0
corrupt[position]=0
badzip=out/'corrupt-deflate.apk';badzip.write_bytes(corrupt)
source={'source_bytes':len(orig),'source_sha256':sha(B),'archive_entry_index':0,'archive_entry_name':'classes.dex'}
try:diff._read_source_bytes(badzip,source,{'format':'Apk'},1024*1024)
except diff.DiffError as error:assert 'cannot read verified DEX source' in str(error)
else:raise AssertionError('corrupt compressed stream accepted')
r=run('handler-budget',['--before',shared,'--after',shared,'--code-digest','--code-max-handler-items','1'],False)
assert b'code handler work limit exceeded' in r.stderr
assert {str(x):sha(x) for x in inputs}==before
(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'fixed raw code-item byte fingerprints, not semantic equivalence or verifier','inputs_before':before,'inputs_after':before,'records':records,'expected_raw_digest':expected,'expected_try_digest':expected_try,'generated_sha256':{x.name:sha(x) for x in (modified,out/'stored.apk',out/'deflated.apk')}},indent=2)+'\n',encoding='utf-8')
print('PASS optional raw code item fingerprints and archive/budget controls')




