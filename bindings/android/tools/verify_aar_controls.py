"""Exercise AAR verifier against deliberately altered local test copies."""
from pathlib import Path
from zipfile import ZipFile
import argparse,hashlib,io,json,struct,subprocess,sys

def main():
    p=argparse.ArgumentParser()
    for name in ['aar','header','readelf','runtime-report','verify','out']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);original=a.aar.read_bytes();before=hashlib.sha256(original).hexdigest()
    cases=['missing-abi','extra-jar','extra-class','wrong-minsdk','wrong-symbol','wrong-alignment','failed-dependency-report'];records=[]
    for name in cases:
        buffer=io.BytesIO()
        with ZipFile(io.BytesIO(original)) as source,ZipFile(buffer,'w') as dest:
            for entry in source.infolist():
                if name=='missing-abi' and entry.filename=='jni/armeabi-v7a/libdexmeguviz.so':continue
                data=source.read(entry.filename)
                if name=='wrong-minsdk' and entry.filename=='AndroidManifest.xml':
                    assert data.count(b'android:minSdkVersion="27"')==1;data=data.replace(b'android:minSdkVersion="27"',b'android:minSdkVersion="26"')
                if name=='wrong-symbol' and entry.filename=='jni/arm64-v8a/libdexmeguviz.so':
                    assert data.count(b'\0dmg_abi_version\0')==1;data=data.replace(b'\0dmg_abi_version\0',b'\0bad_abi_version\0')
                if name=='wrong-alignment' and entry.filename=='jni/arm64-v8a/libdexmeguviz.so':
                    data=bytearray(data);assert data[:5]==b'\x7fELF\x02';off=struct.unpack_from('<Q',data,32)[0];step=struct.unpack_from('<H',data,54)[0];count=struct.unpack_from('<H',data,56)[0]
                    for i in range(count):
                        pos=off+i*step
                        if struct.unpack_from('<I',data,pos)[0]==1:struct.pack_into('<Q',data,pos+48,4096);break
                    else:raise AssertionError('no ELF64 load segment')
                    data=bytes(data)
                if name=='extra-class' and entry.filename=='classes.jar':
                    inner=io.BytesIO()
                    with ZipFile(io.BytesIO(data)) as old,ZipFile(inner,'w') as new:
                        for nested in old.infolist():new.writestr(nested,old.read(nested.filename))
                        new.writestr('kotlin/Injected.class',b'test-only')
                    data=inner.getvalue()
                dest.writestr(entry,data)
            if name=='extra-jar':dest.writestr('libs/test-only.jar',b'test-only')
        mutated=a.out/(name+'.aar');mutated.write_bytes(buffer.getvalue())
        report=a.runtime_report
        if name=='failed-dependency-report':
            report=a.out/(name+'.txt');report.write_text(a.runtime_report.read_text(encoding='utf-8')+'\nFAILED\n',encoding='utf-8')
        cmd=[sys.executable,str(a.verify),'--aar',str(mutated),'--header',str(a.header),'--readelf',str(a.readelf),'--runtime-report',str(report),'--out',str(a.out/(name+'-check'))]
        result=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
        (a.out/(name+'.log')).write_text(result.stdout+result.stderr,encoding='utf-8')
        if result.returncode==0:raise SystemExit('forged AAR was accepted: '+name)
        records.append({'name':name,'exit_code':result.returncode,'diagnostic':(result.stdout+result.stderr)[-600:]})
    after=hashlib.sha256(a.aar.read_bytes()).hexdigest()
    if before!=after:raise SystemExit('original AAR changed')
    (a.out/'summary.json').write_text(json.dumps({'scope':'deliberately altered test copies; not production AARs','original_sha256':before,'rejected':records},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'rejected':len(records),'original_sha256':before}))
if __name__=='__main__':main()
