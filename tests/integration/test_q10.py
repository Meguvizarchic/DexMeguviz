"""Static, independent post-validation model; does not implement a product API."""
import argparse, hashlib, json, struct, subprocess, sys, time, zlib
from pathlib import Path

SHA = '5781e8d4723a2f051d187929072357b8507d7bad0ecc30c9c9e244e2a0ebf0b8'

def read_uleb(b, p):
    n = shift = 0
    for _ in range(5):
        x = b[p]; p += 1; n |= (x & 127) << shift
        if x < 128: return n, p
        shift += 7
    raise ValueError('invalid uleb')

def independently_read_fixture(path):
    b = path.read_bytes()
    assert hashlib.sha256(b).hexdigest() == SHA
    assert b[:8] == b'dex\n035\0' and struct.unpack_from('<I', b, 32)[0] == len(b)
    assert struct.unpack_from('<I', b, 8)[0] == zlib.adler32(b[12:]) & 0xffffffff
    assert b[12:32] == hashlib.sha1(b[32:]).digest()
    u32 = lambda p: struct.unpack_from('<I', b, p)[0]
    assert u32(56) == 36 and u32(88) == 33 and u32(96) == 1
    strings = []
    for i in range(u32(56)):
        pos = u32(u32(60) + 4*i); length, pos = read_uleb(b, pos)
        text = b[pos:pos+length].decode('ascii'); assert b[pos+length] == 0
        strings.append(text)
    types = [strings[u32(u32(68) + 4*i)] for i in range(u32(64))]
    method_off = u32(92); class_off = u32(100); p = u32(class_off+24)
    counts = []
    for _ in range(4): n,p=read_uleb(b,p); counts.append(n)
    assert counts == [0,0,33,0]
    rows = []; index = 0
    for i in range(33):
        declaration = p; delta,p=read_uleb(b,p); flags,p=read_uleb(b,p); code,p=read_uleb(b,p); index += delta
        owner, proto, name = struct.unpack_from('<HHI',b,method_off+8*index)
        assert index == i and flags == 9 and proto == 0 and types[owner] == 'Lfixture/ThirtyThree;'
        assert strings[name] == f'm{i:02d}' and struct.unpack_from('<I',b,code+12)[0] == 1
        assert struct.unpack_from('<H',b,code+16)[0] == 0x000e
        rows.append((index, strings[name], declaration, code))
    return rows

def postvalidate(raw, accepted, unknown=()):
    # A simulated consumer, not a tested product validator or BIL integration.
    names = [r['name'] for r in raw['candidates']]
    hits = [n for n in names if n in accepted]
    uncertain = any(n in unknown for n in names)
    complete = raw['execution_status'] == 'Complete' and raw['coverage'] == 'Complete' and not uncertain
    if len(hits) >= 2: unique = 'Ambiguous'
    elif complete: unique = 'Unique' if hits else 'NoMatch'
    else: unique = 'Undetermined'
    exists = 'Yes' if hits else ('NoMatch' if complete else 'Undetermined')
    return {'accepted':hits,'unique':unique,'exists':exists,'negative_cache_allowed':complete and not hits}

def main():
    p=argparse.ArgumentParser(); p.add_argument('--exe',type=Path,required=True); p.add_argument('--fixture',type=Path,required=True); p.add_argument('--generator',type=Path,required=True); p.add_argument('--output',type=Path); p.add_argument('--root',type=Path)
    a=p.parse_args()
    if a.output is None:
        if a.root is None: p.error('one of --output or --root is required')
        a.output=a.root/'docs/evidence/q10-model'/('run-'+str(time.time_ns()))
    a.output.mkdir(parents=True,exist_ok=False)
    rebuilt=a.output/'rebuilt'
    generated=subprocess.run([sys.executable,str(a.generator),'--output',str(rebuilt)],capture_output=True,timeout=30)
    assert generated.returncode==0, generated.stderr.decode('utf-8','replace')
    assert (rebuilt/'q10-33.dex').read_bytes()==a.fixture.read_bytes()
    assert (rebuilt/'expected.json').read_bytes()==(a.fixture.parent/'expected.json').read_bytes()
    authored=independently_read_fixture(a.fixture)
    exe_hash=hashlib.sha256(a.exe.read_bytes()).hexdigest()
    def run(name,intent,cap,incomplete=False):
        query={'schema_version':1,'relation':'method_defs','intent':intent,'max_results':cap}
        q=a.output/(name+'.query.json'); q.write_text(json.dumps(query),encoding='utf-8')
        cmd=[str(a.exe),'query',str(a.fixture),'--query',str(q),'--json']
        if incomplete: cmd.append('--scope-incomplete')
        r=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8')
        (a.output/(name+'.stdout.json')).write_text(r.stdout,encoding='utf-8')
        (a.output/(name+'.stderr.txt')).write_text(r.stderr,encoding='utf-8')
        raw=json.loads(r.stdout); candidates=raw['candidates']
        assert raw['source_sha256']==SHA and raw['total_methods']==33
        for actual, expected in zip(candidates,authored):
            index,method,declaration,code=expected
            assert (actual['method_index'],actual['name'],actual['declaration_offset'],actual['code_offset']) == (index,method,declaration,code)
            assert actual['owner']=='Lfixture/ThirtyThree;' and actual['prototype']=='()V' and actual['access_flags']==9
            assert actual['source_index']==0 and actual['input_index']==0 and actual['source_sha256']==SHA
            for k in ('content_id','occurrence_id','snapshot_id','logical_dex_id'): assert actual[k]==raw[k]
        return r.returncode,raw
    rc,cap=run('cap32','enumerate',32)
    assert rc==3 and (cap['execution_status'],cap['coverage'],cap['reason'])==('BudgetExceeded','Partial','ResultLimit') and len(cap['candidates'])==32
    cap_result=postvalidate(cap,{'m32'}); assert cap_result['unique']=='Undetermined' and not cap_result['negative_cache_allowed']
    rc,full=run('full33','enumerate',33)
    assert rc==0 and (full['execution_status'],full['coverage'])==('Complete','Complete') and len(full['candidates'])==33
    full_result=postvalidate(full,{'m32'}); assert full_result['accepted']==['m32'] and full_result['unique']=='Unique'
    assert postvalidate(full,set())['negative_cache_allowed']
    assert postvalidate(full,{'m32'},{'m10'})['unique']=='Undetermined'
    assert not postvalidate(full,set(),{'m10'})['negative_cache_allowed']
    rc,partial=run('scope_incomplete','enumerate',33,True)
    assert rc==0 and partial['coverage']=='Partial' and len(partial['candidates'])==33
    assert postvalidate(partial,{'m32'})['unique']=='Undetermined'
    assert postvalidate(partial,{'m32'})['exists']=='Yes'
    rc,unique=run('raw_unique','unique',33)
    assert rc==0 and len(unique['candidates'])==2 and unique['coverage']=='Partial'
    assert postvalidate(unique,{'m32'})['unique']=='Undetermined'
    assert postvalidate(unique,{'m00','m01'})['unique']=='Ambiguous'
    rc,exists=run('raw_exists','exists',33)
    assert rc==0 and len(exists['candidates'])==1 and exists['coverage']=='Partial'
    assert postvalidate(exists,{'m32'})['exists']=='Undetermined'
    assert hashlib.sha256(a.exe.read_bytes()).hexdigest()==exe_hash and hashlib.sha256(a.fixture.read_bytes()).hexdigest()==SHA
    summary={'fixture_sha256':SHA,'exe_sha256':exe_hash,'cap32':cap_result,'full33':full_result,
             'scope_incomplete_unique':postvalidate(partial,{'m32'}),'raw_unique_after_business_validation':postvalidate(unique,{'m32'}),
             'raw_exists_after_business_validation':postvalidate(exists,{'m32'}),
             'scope':'test-only simulated validation; no BIL, ART, device or production business validator exercised'}
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8'); print(json.dumps(summary,ensure_ascii=False))
if __name__=='__main__': main()
