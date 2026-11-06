"""Configure/build/test with discovered local CMake; no downloads or installs."""
import argparse
import glob
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--preset',choices=['host-debug','host-asan'],default='host-debug')
    parser.add_argument('--cmake')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    candidates=[args.cmake,shutil.which('cmake')]
    if os.name=='nt':
        candidates+=sorted(glob.glob(r'C:\Program Files\Microsoft Visual Studio\*\*\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'),reverse=True)
    cmake=next((Path(x) for x in candidates if x and Path(x).is_file()),None)
    if cmake is None:raise SystemExit('CMake not found; pass --cmake with an installed executable')
    ctest=cmake.with_name('ctest.exe' if os.name=='nt' else 'ctest')
    environment=os.environ.copy()
    if os.name=='nt':
        compiler_dirs=sorted(glob.glob(r'C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64'),reverse=True)
        environment['PATH']=os.pathsep.join(compiler_dirs+[str(cmake.parent),environment.get('PATH','')])
    evidence=root/'docs/evidence'/args.preset/('run-'+str(time.time_ns()))
    evidence.mkdir(parents=True,exist_ok=True)
    commands=[
        [sys.executable,'tests/fixtures/generators/generate_dex.py'],
        [str(cmake),'--preset',args.preset],
        [str(cmake),'--build','--preset',args.preset,'--parallel','4'],
        [str(ctest),'--preset',args.preset,'--output-on-failure','--output-junit',str(evidence/'ctest.xml')],
    ]
    records=[]
    for i,command in enumerate(commands):
        started=time.monotonic()
        result=subprocess.run(command,cwd=root,env=environment,capture_output=True,text=True,encoding='utf-8',errors='replace')
        output=result.stdout+result.stderr
        (evidence/f'{i:02d}.log').write_text(output,encoding='utf-8')
        records.append({'argv':command,'cwd':str(root),'exit_code':result.returncode,'elapsed_seconds':round(time.monotonic()-started,3),'log':f'{i:02d}.log'})
        (evidence/'commands.json').write_text(json.dumps(records,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(output[-16000:],flush=True)
        if result.returncode:raise SystemExit(result.returncode)
    (evidence.parent/'latest.json').write_text(json.dumps({'evidence':str(evidence.relative_to(root)),'all_passed':True})+'\n',encoding='utf-8')
    print(json.dumps({'preset':args.preset,'commands':len(records),'all_passed':True}))

if __name__=='__main__':main()
