"""Compile-only Android smoke. Never starts adb, installs APKs, or downloads tools."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--ndk',type=Path,required=True)
    p.add_argument('--cmake',type=Path,required=True)
    p.add_argument('--ninja',type=Path,required=True)
    p.add_argument('--abi',choices=['arm64-v8a','armeabi-v7a'],required=True)
    args=p.parse_args()
    root=Path(__file__).resolve().parents[1]
    for f in [args.cmake,args.ninja,args.ndk/'build/cmake/android.toolchain.cmake']:
        if not f.is_file():raise SystemExit('Missing installed tool: '+str(f))
    build=root/'build'/('android-'+args.abi)
    evidence=root/'docs/evidence'/('android-'+args.abi)/('run-'+str(time.time_ns()))
    evidence.mkdir(parents=True,exist_ok=True)
    commands=[
        [str(args.cmake),'-S',str(root),'-B',str(build),'-G','Ninja',
         '-DCMAKE_MAKE_PROGRAM='+str(args.ninja),'-DCMAKE_TOOLCHAIN_FILE='+str(args.ndk/'build/cmake/android.toolchain.cmake'),
         '-DANDROID_ABI='+args.abi,'-DANDROID_PLATFORM=android-27','-DANDROID_STL=c++_static',
         '-DDMG_BUILD_TESTS=OFF','-DCMAKE_BUILD_TYPE=Debug'],
        [str(args.cmake),'--build',str(build),'--parallel','4'],
    ]
    records=[]
    for i,command in enumerate(commands):
        result=subprocess.run(command,cwd=root,capture_output=True,text=True,encoding='utf-8',errors='replace')
        output=result.stdout+result.stderr
        (evidence/f'{i:02d}.log').write_text(output,encoding='utf-8')
        records.append({'argv':command,'exit_code':result.returncode,'log':f'{i:02d}.log'})
        (evidence/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
        print(output[-10000:],flush=True)
        if result.returncode:raise SystemExit(result.returncode)
    files={}
    for name in ['libdexmeguviz_core.a','dexmeguviz']:
        f=build/name;files[name]={'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}
    summary={'scope':'compile-only; no Android runtime, AAR, JNI or page-size validation','abi':args.abi,'api_level':27,'artifacts':files,'evidence':str(evidence.relative_to(root))}
    (evidence.parent/'latest.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary))
if __name__=='__main__':main()
