"""Check MSVC DLL export and host dependency text; not other-platform proof."""
import argparse,hashlib,json,re
from pathlib import Path

p=argparse.ArgumentParser()
for name in ('exports','static-host','dynamic-host','out'):p.add_argument('--'+name,required=True,type=Path)
a=p.parse_args(); data={name:getattr(a,name.replace('-','_')).read_bytes() for name in ('exports','static-host','dynamic-host')}
text={name:value.decode('utf-8',errors='replace').lower() for name,value in data.items()}
symbols=re.findall(r'^\s*\d+\s+[0-9a-f]+\s+[0-9a-f]+\s+(\S+)',text['exports'],re.M)
if symbols!=['dmg_test_private_count']:raise SystemExit('unexpected private DLL exports: '+repr(symbols))
probe='dmg_sqlite_private_probe.dll';host='dmg_sqlite_host_shared.dll'
if probe not in text['static-host'] or host in text['static-host']:raise SystemExit('unexpected static-host dependencies')
if probe not in text['dynamic-host'] or host not in text['dynamic-host']:raise SystemExit('unexpected dynamic-host dependencies')
if a.out.exists():raise SystemExit('output exists')
a.out.write_text(json.dumps({'outcome':'passed','exported':symbols,'static_host':{'probe':True,'shared_host':False},
 'dynamic_host':{'probe':True,'shared_host':True},'input_sha256':{name:hashlib.sha256(value).hexdigest() for name,value in data.items()},
 'scope':'Windows MSVC fixed test DLL and host executables only; no general platform or sandbox proof'},indent=2)+'\n',encoding='utf-8')
print('PASS private DLL export list and static/dynamic host dependencies')
