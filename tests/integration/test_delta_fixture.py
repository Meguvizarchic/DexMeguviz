"""Independent raw-byte and CLI checks for four class_data delta groups."""
import argparse, hashlib, json, struct, subprocess, sys, time, zlib
from pathlib import Path

FIXTURE_SHA='ea2e71c8092b0837e24fe3b53ecbe96468ce825c1db6fe3c80b178afd85e2d50'
RAW=bytes.fromhex('03 03 03 03 01 09 02 09 02 09 00 01 02 01 02 01 01 89 02 00 02 09 a0 03 02 02 b4 03 00 81 08 00 02 01 b4 03 02 81 02 00')
# (name, ID-table index, declaration offset, flags, code offset); authored separately
# from the native reader, with interleaved ID-table order forcing group reset.
FIELDS=[('b',1,458,9,None),('d',3,460,9,None),('f',5,462,9,None),('a',0,464,1,None),('c',2,466,1,None),('e',4,468,1,None)]
METHODS=[('b',1,470,0x109,0),('d',3,474,9,416),('f',5,478,2,436),('a',0,482,0x401,0),('c',2,486,1,436),('e',4,490,0x101,0)]

def negative_diagnostic(name):
    if name.endswith('-duplicate'): return 'duplicate index in a class_data sequence'
    if name.endswith('-out-of-range') or name=='delta-overflow': return 'class_data delta index is out of range'
    if name in ('duplicate-field-across-groups','duplicate-method-across-groups'):
        return 'duplicate member definition or mismatched owner'
    if name in ('static-field-wrong-group','instance-field-wrong-group'):
        return 'static/instance field group mismatch'
    if name in ('direct-method-wrong-group','virtual-method-wrong-group'):
        return 'direct/virtual method group mismatch'
    if name=='delta-overlong': return 'ULEB128 exceeds 32 bits'
    if name=='delta-section-end-truncated': return 'truncated LEB128 (offset 494)'
    raise ValueError('no expected diagnostic for negative case: '+name)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--exe',type=Path,required=True);ap.add_argument('--fixture-dir',type=Path);ap.add_argument('--output',type=Path);ap.add_argument('--root',type=Path);args=ap.parse_args()
    if args.output is None:
        if args.root is None: ap.error('one of --root or --output is required')
        args.output=args.root/'docs/evidence/class-data-delta'/('run-'+str(time.time_ns()))
    args.output.mkdir(parents=True,exist_ok=False)
    if args.fixture_dir is None:
        args.fixture_dir=args.output/'input'
        generator=Path(__file__).with_name('generate_delta_fixture.py')
        p=subprocess.run([sys.executable,str(generator),'--output',str(args.fixture_dir)],capture_output=True,timeout=30);assert p.returncode==0,(p.stdout,p.stderr)
    fixture=args.fixture_dir/'four-groups.dex';data=fixture.read_bytes();exe_hash=hashlib.sha256(args.exe.read_bytes()).hexdigest()
    assert len(data)==632 and hashlib.sha256(data).hexdigest()==FIXTURE_SHA
    assert data[:8]==b'dex\n035\0' and data[454:494]==RAW
    assert data[12:32]==hashlib.sha1(data[32:]).digest() and struct.unpack_from('<I',data,8)[0]==zlib.adler32(data[12:])&0xffffffff
    assert struct.unpack_from('<I',data,52)[0]==496 and struct.unpack_from('<I',data,96)[0]==1
    manifest=json.loads((args.fixture_dir/'manifest.json').read_text(encoding='utf-8'));cases=manifest['variants'];assert len(cases)==19
    rebuilt=args.output/'rebuilt';generator=Path(__file__).with_name('generate_delta_fixture.py')
    p=subprocess.run([sys.executable,str(generator),'--output',str(rebuilt)],capture_output=True,timeout=30);assert p.returncode==0,(p.stdout,p.stderr)
    for name,item in cases.items():
        a=(args.fixture_dir/(name+'.dex')).read_bytes();b=(rebuilt/(name+'.dex')).read_bytes()
        assert hashlib.sha256(a).hexdigest()==item['sha256'] and a==b
        assert a[12:32]==hashlib.sha1(a[32:]).digest() and struct.unpack_from('<I',a,8)[0]==zlib.adler32(a[12:])&0xffffffff
    control=(args.fixture_dir/'delta-section-end-control.dex').read_bytes()
    truncated=(args.fixture_dir/'delta-section-end-truncated.dex').read_bytes()
    assert len(control)==len(truncated)==644 and struct.unpack_from('<I',control,52)[0]==496
    assert struct.unpack_from('<I',control,496)[0]==12 and control[490:496]==bytes.fromhex('02 81 02 00 00 00')
    assert truncated[490:496]==bytes.fromhex('02 81 02 80 00 00')
    assert control[32:493]==truncated[32:493] and control[494:]==truncated[494:]
    assert struct.unpack_from('<HHII',control,496+4+10*12)==(0x2005,0,1,494)
    records=[]
    def run(name,command,expect):
        p=subprocess.run(command,capture_output=True,timeout=30)
        stdout=p.stdout.decode('utf-8','replace');stderr=p.stderr.decode('utf-8','replace')
        records.append({'name':name,'exit_code':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr':stderr[:1200]})
        if expect=='Complete':assert p.returncode==0,(name,p.returncode,stderr)
        else:assert p.returncode==2 and 'CorruptInput' in stderr,(name,p.returncode,stderr)
        return json.loads(stdout) if p.returncode==0 else None
    inspect=run('valid-inspect',[str(args.exe),'inspect',str(fixture),'--json'],'Complete')
    assert inspect['coverage']=='Complete' and inspect['counts']['method_defs']==6 and inspect['counts']['method_refs']==7
    for name in cases:
        if name!='four-groups':
            expected='Complete' if name=='delta-section-end-control' else 'CorruptInput'
            result=run(name,[str(args.exe),'inspect',str(args.fixture_dir/(name+'.dex')),'--json'],expected)
            if name=='delta-section-end-control':
                assert result['counts']['method_defs']==6 and result['counts']['method_refs']==7
            else:
                expected_reason=negative_diagnostic(name)
                records[-1]['expected_diagnostic']=expected_reason
                assert expected_reason in records[-1]['stderr'],(name,records[-1]['stderr'])
    def query(rel,repeat=False):
        q=args.output/(rel+('-repeat' if repeat else '')+'.json');q.write_text(json.dumps({'schema_version':1,'relation':rel,'max_results':100}),encoding='utf-8')
        command=[str(args.exe),'query',str(fixture),'--query',str(q),'--json']
        if repeat:command += ['--source',str(fixture)]
        return run(rel+('-repeat' if repeat else ''),command,'Complete')
    for rel in ['field_defs','method_defs']:
        result=query(rel,True);expected=FIELDS if rel=='field_defs' else METHODS
        assert result['coverage']=='Complete' and len(result['candidates'])==12
        sources=result['sources'];assert len(sources)==2 and sources[0]['content_id']==sources[1]['content_id'] and sources[0]['occurrence_id']!=sources[1]['occurrence_id']
        for source in range(2):
            rows=[r for r in result['candidates'] if r['source_index']==source]
            assert len(rows)==6
            for row,(name,index,offset,flags,code) in zip(rows,expected):
                assert row['name']==name and row['owner']=='Lsample/Delta;' and row['access_flags']==flags
                assert row['occurrence_id']==sources[source]['occurrence_id']
                if rel=='field_defs':
                    assert row['reference_index']==index and row['record_offset']==offset and row['definition_offset']==offset and row['code_offset'] is None
                else:assert row['method_index']==index and row['declaration_offset']==offset and row['code_offset']==code
    for rel in ['field_refs','method_refs']:
        result=query(rel);rows=result['candidates'];assert len(rows)==7
        external=next(r for r in rows if r['reference_index']==6)
        assert external['name']=='z' and external['owner']=='Lx/External;' and external['has_local_definition'] is False
        assert external['definition_offset'] is None and external['access_flags'] is None and external['code_offset'] is None
    assert hashlib.sha256(args.exe.read_bytes()).hexdigest()==exe_hash
    summary={'cases':len(records),'failed':0,'fixture_sha256':FIXTURE_SHA,'exe_sha256':exe_hash,'scope':'synthetic static metadata only; no ART/device evidence','records':records}
    (args.output/'results.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'cases':len(records),'failed':0,'fixture_sha256':FIXTURE_SHA}))
if __name__=='__main__':main()
