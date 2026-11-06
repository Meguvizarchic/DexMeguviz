"""Verify hostile SQLite build macros fail before compiling the private TU."""
import argparse,hashlib,json,os,subprocess,time
from pathlib import Path

p=argparse.ArgumentParser()
for name in ('root','cmake','out'):p.add_argument('--'+name,required=True,type=Path)
a=p.parse_args();root=a.root.resolve();out=a.out.resolve();cmake=a.cmake.resolve()
workspace=Path(r'<LOCAL_PATH>').resolve()
if not root.is_relative_to(workspace) or not out.is_relative_to(workspace) or out==root or out.exists():
    raise SystemExit('root/out must be separate, new workspace paths')
out.mkdir(parents=True)
inputs=[root/'adapters/sqlite/private_sqlite.c',root/'third_party/sqlite/sqlite3.c',root/'CMakeLists.txt']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
before={str(p):sha(p) for p in inputs}
cases=[('api','/DSQLITE_API=extern','Private SQLite linkage must not be overridden'),
       ('private','/DSQLITE_PRIVATE=extern','Private SQLite linkage must not be overridden'),
       ('extra-init','/DSQLITE_EXTRA_INIT=host_hook','Unexpected SQLite extension or test hooks are forbidden'),
       ('no-autoinit','/DSQLITE_OMIT_AUTOINIT=1','Private SQLite requires the configured desktop build options'),
       ('custom-os','/DSQLITE_OS_OTHER=1','Private SQLite requires the tested built-in platform VFS model'),
       ('kv-os','/DSQLITE_OS_KV=1','Private SQLite requires the tested built-in platform VFS model'),
       ('omit-wsd','/DSQLITE_OMIT_WSD=1','Private SQLite requires the tested built-in platform VFS model'),
       ('no-memstatus','/DSQLITE_DEFAULT_MEMSTATUS=0','Private SQLite heap budget requires memory status accounting')]
records=[]
for name,flags,expected in cases:
    target=out/name;target.mkdir();build=target/'build'
    commands=[('configure',[str(cmake),'-S',str(root),'-B',str(build),'-G','Visual Studio 18 2026',
              '-DDMG_WITH_SQLITE=ON','-DDMG_BUILD_TESTS=OFF','-DDMG_BUILD_SQLITE_PROTO_TESTS=OFF',
              '-DDMG_BUILD_FUZZERS=OFF','-DCMAKE_C_FLAGS='+flags]),
              ('build',[str(cmake),'--build',str(build),'--config','Debug','--target','dmg_sqlite_private','--parallel','2'])]
    for label,cmd in commands:
        started=time.monotonic();r=subprocess.run(cmd,cwd=root,capture_output=True,timeout=300)
        (target/(label+'.stdout.log')).write_bytes(r.stdout);(target/(label+'.stderr.log')).write_bytes(r.stderr)
        combined=(r.stdout+r.stderr).decode('utf-8',errors='replace')
        records.append({'case':name,'step':label,'argv':cmd,'exit_code':r.returncode,'seconds':round(time.monotonic()-started,2)})
        if label=='configure' and r.returncode:raise SystemExit(name+' configure failed')
        if label=='build' and (not r.returncode or expected not in combined):raise SystemExit(name+' did not fail at expected guard')
    print(name,'expected guard rejected',flush=True)
after={str(p):sha(p) for p in inputs};assert before==after
(out/'summary.json').write_text(json.dumps({'outcome':'passed','cases':len(cases),'input_sha256':before,'records':records,
 'scope':'MSVC compile-time rejection only; no other-platform or runtime sandbox claim'},indent=2)+'\n',encoding='utf-8')
print('PASS private SQLite compile-time guards',flush=True)

