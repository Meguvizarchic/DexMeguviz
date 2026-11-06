"""Numeric-v7 query plus optional DEX checksum diagnostics, independently checked."""
from pathlib import Path
import argparse, hashlib, json, struct, subprocess, tempfile, zlib

p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--root',type=Path,required=True);a=p.parse_args()
data=a.fixture.read_bytes()
assert hashlib.sha256(data).hexdigest()=='45493d9c18a659507a1929467be3420bba23e408f906641d253da59d73c92699'
authored=json.loads((a.root/'tests/fixtures/generated/method_facts/expected.json').read_text(encoding='utf-8'))
off=authored['uses']['code_offset'];assert struct.unpack_from('<8H',data,off+16)==(0xf012,0x0016,0xfffe,0x0015,0x8000,0x001a,10,0x000e)

def digest(blob):
 expected_adler=struct.unpack_from('<I',blob,8)[0];actual_adler=zlib.adler32(blob[12:])&0xffffffff
 expected_sha1=blob[12:32].hex();actual_sha1=hashlib.sha1(blob[32:]).hexdigest()
 return {'input_bytes':len(blob),'adler32_expected':expected_adler,'adler32_actual':actual_adler,
         'adler32_matches':expected_adler==actual_adler,'sha1_expected':expected_sha1,
         'sha1_actual':actual_sha1,'sha1_matches':expected_sha1==actual_sha1}

with tempfile.TemporaryDirectory(prefix='dmg-numeric-checksum-') as td:
 root=Path(td);a1=bytearray(data);a1[8]^=1
 s1=bytearray(data);s1[12]^=1;struct.pack_into('<I',s1,8,zlib.adler32(s1[12:])&0xffffffff)
 files=[]
 for name,contents in [('valid.dex',data),('bad-adler.dex',a1),('bad-sha.dex',s1)]:
  path=root/name;path.write_bytes(contents);files.append(path)
 queries={'schema_version':1,'relation':'method_defs','where':{'all':[{'name':'uses'},
          {'numeric_bits':{'width':64,'bits':'fffffffffffffffe','kind':'constant'}}]},'intent':'enumerate'}
 query=root/'query.json';query.write_text(json.dumps(queries),encoding='utf-8')
 def invoke(with_checksums):
  cmd=[str(a.exe),'query',str(files[0]),'--source',str(files[1]),'--source',str(files[2]),'--query',str(query),'--json']
  if with_checksums:cmd.append('--dex-checksums')
  r=subprocess.run(cmd,capture_output=True,timeout=30)
  assert r.returncode==0,(r.returncode,r.stdout,r.stderr)
  return json.loads(r.stdout)
 plain,checked=invoke(False),invoke(True)
 assert plain['query_id']==checked['query_id'] and checked['query_id'].startswith('query:v7:')
 assert checked['profile']=='dex-query-numeric-v7' and checked['execution_status']=='Complete' and checked['coverage']=='Complete'
 assert plain['validation']['dex_checksum']=='NotVerified' and 'dex_checksums' not in plain
 assert checked['validation']['dex_checksum']=='PerSourceCompared' and len(checked['dex_checksums'])==3
 for index,(item,path) in enumerate(zip(checked['dex_checksums'],files)):
  assert item=={'source_index':index,**digest(path.read_bytes())}
 assert checked['dex_checksums'][0]['adler32_matches'] and checked['dex_checksums'][0]['sha1_matches']
 assert not checked['dex_checksums'][1]['adler32_matches'] and checked['dex_checksums'][1]['sha1_matches']
 assert checked['dex_checksums'][2]['adler32_matches'] and not checked['dex_checksums'][2]['sha1_matches']
 assert len(plain['candidates'])==len(checked['candidates'])==3
 for index,(before,row,path) in enumerate(zip(plain['candidates'],checked['candidates'],files)):
  assert row['source_index']==index and row['name']=='uses'
  assert row['source_sha256']==hashlib.sha256(path.read_bytes()).hexdigest()
  assert row['occurrence_id']==before['occurrence_id'] and row['snapshot_id']==before['snapshot_id']
  witnesses=[w for w in row['evidence'] if w['kind']=='numeric_literal'];assert len(witnesses)==1
  w=witnesses[0];assert (w['dex_pc'],w['opcode'],w['width_bits'],w['bits'],w['literal_kind'])==(1,0x16,64,'fffffffffffffffe','constant')
  assert w['entity']=={'relation':'method_defs','source_index':index,'local_index':2}
  assert row['evidence']==before['evidence']
 print('PASS numeric v7 with optional per-source DEX checksum comparison; raw bytes, mismatch isolation, origins and numeric evidence checked')
