"""Inspect a built AAR and its ELF exports without running Android binaries."""
from pathlib import Path
from zipfile import ZipFile
import argparse,hashlib,io,json,re,subprocess,xml.etree.ElementTree as ET

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--aar',type=Path,required=True)
    p.add_argument('--header',type=Path,required=True)
    p.add_argument('--readelf',type=Path,required=True)
    p.add_argument('--runtime-report',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    data=a.aar.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
    header=a.header.read_text(encoding='utf-8')
    expected=set(re.findall(r'\b(?:dmg_status|void|uint32_t|const\s+char\s*\*)\s*(dmg_[A-Za-z0-9_]+)\s*\(',header))
    if not expected:raise SystemExit('no C API declarations found')
    jni={'Java_io_github_jichuo1_dexmeguviz_NativeEngine_abiVersion','Java_io_github_jichuo1_dexmeguviz_NativeEngine_capabilities',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenRawDex',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeSnapshotInfo',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeClose'}
    deps=a.runtime_report.read_text(encoding='utf-8',errors='replace')
    if 'releaseRuntimeClasspath' not in deps or 'No dependencies' not in deps or 'FAILED' in deps:raise SystemExit('runtime classpath not proven empty')
    result={'aar_sha256':sha(data),'aar_bytes':len(data),'runtime_classpath':'No dependencies','public_c_export_count':len(expected),'abis':{},'scope':'static AAR/ELF inspection only; no Android load, runtime, APK packaging or JNI query claim'}
    with ZipFile(io.BytesIO(data)) as z:
        wanted={'jni/arm64-v8a/libdexmeguviz.so','jni/armeabi-v7a/libdexmeguviz.so'}
        if {n for n in z.namelist() if n.endswith('.so')}!=wanted:raise SystemExit('unexpected shared libraries')
        if any(n.startswith('libs/') and n.endswith('.jar') for n in z.namelist()):raise SystemExit('unexpected embedded jar')
        manifest=ET.fromstring(z.read('AndroidManifest.xml'));sdk=manifest.find('uses-sdk')
        if sdk is None or sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion')!='27':raise SystemExit('wrong minSdk')
        if 'io.github.jichuo1.dexmeguviz.NativeEngine' not in z.read('proguard.txt').decode('utf-8'):raise SystemExit('JNI keep rule missing')
        with ZipFile(io.BytesIO(z.read('classes.jar'))) as classes:
            names=[x for x in classes.namelist() if x.endswith('.class')]
            expected_classes={'io/github/jichuo1/dexmeguviz/NativeEngine.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$Snapshot.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$SnapshotInfo.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$NativeFailure.class'}
            if set(names)!=expected_classes or len(names)!=len(expected_classes):raise SystemExit('unexpected class files')
            code=classes.read('io/github/jichuo1/dexmeguviz/NativeEngine.class')
            if b'kotlin/' in code or b'abiVersion' not in code or b'capabilities' not in code:raise SystemExit('unexpected Java class contents')
            for name in names:
                code=classes.read(name)
                if b'kotlin/' in code or code[:4]!=b'\xca\xfe\xba\xbe' or int.from_bytes(code[6:8],'big')!=61:raise SystemExit('unexpected Kotlin or Java class version')
            result['java_class_major']=61
        result['aar_entries']=z.namelist();result['aar_metadata']=z.read('META-INF/com/android/build/gradle/aar-metadata.properties').decode('utf-8')
        for abi,machine in [('arm64-v8a','AArch64'),('armeabi-v7a','ARM')]:
            member='jni/'+abi+'/libdexmeguviz.so';blob=z.read(member);directory=a.out/abi;directory.mkdir();local=directory/'libdexmeguviz.so';local.write_bytes(blob)
            command=[str(a.readelf),'--wide','--file-header','--program-headers','--dynamic-table','--dyn-syms',str(local)]
            proc=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace')
            (directory/'readelf.stdout.log').write_text(proc.stdout,encoding='utf-8');(directory/'readelf.stderr.log').write_text(proc.stderr,encoding='utf-8')
            if proc.returncode or not re.search(r'^\s*Machine:\s+'+re.escape(machine)+r'\s*$',proc.stdout,re.M):raise SystemExit('readelf or architecture failure: '+abi)
            soname=re.findall(r'\(SONAME\).*\[(.*?)\]',proc.stdout);needed=sorted(re.findall(r'\(NEEDED\).*\[(.*?)\]',proc.stdout))
            if soname!=['libdexmeguviz.so'] or needed!=['libc.so','libdl.so','libm.so']:raise SystemExit('unexpected native dependencies: '+abi)
            loads=[];exports=[];undefined=[]
            for line in proc.stdout.splitlines():
                parts=line.split()
                if parts and parts[0]=='LOAD':
                    offset,vaddr,align=int(parts[1],16),int(parts[2],16),int(parts[-1],16)
                    if align<16384 or offset%align!=vaddr%align:raise SystemExit('invalid load alignment: '+abi)
                    loads.append({'offset':offset,'vaddr':vaddr,'alignment':align})
                m=re.match(r'\s*\d+:\s+\S+\s+\d+\s+\S+\s+(GLOBAL|WEAK)\s+DEFAULT\s+(\S+)\s+(\S+)',line)
                if m:
                    name=m.group(3).split('@')[0]
                    (undefined if m.group(2)=='UND' else exports).append(name)
            if not loads or set(exports)!=(expected|jni):raise SystemExit('unexpected or missing exports: '+abi)
            result['abis'][abi]={'bytes':len(blob),'sha256':sha(blob),'machine':machine,'soname':soname[0],'needed':needed,'load_segments':loads,'exports':sorted(exports),'undefined':sorted(set(undefined)),'aar_compression':z.getinfo(member).compress_type}
    (a.out/'audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'aar_sha256':result['aar_sha256'],'runtime_classpath':result['runtime_classpath'],'exports_per_abi':len(expected)+len(jni),'scope':result['scope']}))
if __name__=='__main__':main()
