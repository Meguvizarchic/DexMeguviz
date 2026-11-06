"""Independent Python hashlib/zlib oracle for optional per-source DEX checks."""
import argparse,hashlib,json,struct,subprocess,tempfile,zipfile,zlib
from pathlib import Path

def expected(data):
    adler_expected=struct.unpack_from('<I',data,8)[0]
    adler_actual=zlib.adler32(data[12:])&0xffffffff
    sha_expected=data[12:32].hex()
    sha_actual=hashlib.sha1(data[32:]).hexdigest()
    return dict(input_bytes=len(data),adler32_expected=adler_expected,adler32_actual=adler_actual,
                adler32_matches=adler_expected==adler_actual,sha1_expected=sha_expected,
                sha1_actual=sha_actual,sha1_matches=sha_expected==sha_actual)

def check(exe,arguments,dexes,enabled=True):
    run=subprocess.run([str(exe),*map(str,arguments)],capture_output=True,text=True,encoding='utf-8',timeout=60)
    assert run.returncode==0,(run.returncode,run.stderr,run.stdout)
    out=json.loads(run.stdout)
    assert out['execution_status']=='Complete'
    if not enabled:
        assert 'dex_checksums' not in out and out['validation']['dex_checksum']=='NotVerified'
        return
    assert out['validation']['dex_checksum']=='PerSourceCompared'
    assert len(out['dex_checksums'])==len(dexes)==len(out['sources'])
    for index,(actual,data) in enumerate(zip(out['dex_checksums'],dexes)):
        assert actual==dict(source_index=index,**expected(data))
        assert out['sources'][index]['source_sha256']==hashlib.sha256(data).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--archive',type=Path,required=True);a=p.parse_args()
    original=a.fixture.read_bytes()
    assert expected(original)['adler32_matches'] and expected(original)['sha1_matches']
    with tempfile.TemporaryDirectory(prefix='dex-checksums-') as temp:
        root=Path(temp);query=root/'query.json';query.write_text('{"schema_version":1,"relation":"method_defs","max_results":64}',encoding='utf-8')
        altered_adler=bytearray(original);altered_adler[8]^=1
        altered_both=bytearray(original);altered_both[12]^=1
        altered_sha=bytearray(altered_both);struct.pack_into('<I',altered_sha,8,zlib.adler32(altered_sha[12:])&0xffffffff)
        cases=[original,altered_adler,altered_both,altered_sha]
        assert [(expected(d)['adler32_matches'],expected(d)['sha1_matches']) for d in cases]==[(True,True),(False,True),(False,False),(True,False)]
        for index,data in enumerate(cases):
            path=root/f'case-{index}.dex';path.write_bytes(data)
            check(a.exe,['inspect',path,'--json','--dex-checksums'],[data])
            check(a.exe,['query',path,'--query',query,'--json','--dex-checksums'],[data])
        check(a.exe,['inspect',a.fixture,'--json'],[original],False)
        for version in ('035','037','038','039','040'):
            path=a.fixture.parent.parent/f'metadata-{version}.dex'
            data=path.read_bytes()
            assert data[4:7].decode('ascii')==version
            check(a.exe,['inspect',path,'--json','--dex-checksums'],[data])
        with zipfile.ZipFile(a.archive) as archive:
            dexes=[archive.read(name) for name in ('classes.dex','classes2.dex')]
        check(a.exe,['inspect',a.archive,'--json','--dex-checksums'],dexes)
        check(a.exe,['inspect',a.fixture,'--source',a.fixture,'--json','--dex-checksums'],[original,original])
    print('PASS independent SHA-1/Adler-32 oracle: four raw states, query, APK and repeated occurrence')
if __name__=='__main__':main()
