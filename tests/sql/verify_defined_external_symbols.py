"""Check defined MSVC external symbols of the private SQLite object only."""
import argparse,json,re,hashlib
from pathlib import Path

p=argparse.ArgumentParser()
for name in ('debug','asan','normal','out'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args()
wrapper_names=('bind_parameter_count','bind_int64','bind_null','bind_text','close','column_bytes','column_count','column_int64',
               'column_text','column_type','context_db_handle','create_module_v2','declare_vtab','finalize','limit','open_v2',
               'prepare_v2','reset','clear_bindings','stmt_status','progress_handler','result_error_toobig','result_error_nomem','result_error_code','result_int64','result_null','result_text',
               'set_authorizer','step','stmt_readonly','stricmp','value_type','value_int64','vtab_in','vtab_in_first','vtab_in_next','configure_heap_limit','heap_snapshot')
base={'dmg_private_sqlite3_'+name for name in wrapper_names}
test={'dmg_private_sqlite3_test_config_log','dmg_private_sqlite3_test_exec','dmg_private_sqlite3_test_default_vfs_is'}
pattern=re.compile(r'^.*?\bSECT[0-9A-F]+\b.*?\bExternal\b\s+\|\s+(\S+)',re.M)
result={}
for mode,path in [('debug',a.debug),('asan',a.asan),('normal',a.normal)]:
    data=path.read_bytes();text=data.decode('utf-8',errors='replace');names=set(pattern.findall(text))
    expected=base|(test if mode!='normal' else set())
    actual={name for name in names if name.startswith('dmg_private_sqlite3_')}
    if actual!=expected:raise SystemExit(mode+' wrapper mismatch '+repr(actual^expected))
    compiler={name for name in names if name=='localtime_s' or re.fullmatch(r'__(?:real|xmm|ymm|zmm)@[0-9A-Fa-f]+',name)}
    unknown=names-actual-compiler
    if unknown:raise SystemExit(mode+' unexpected defined external symbols '+repr(sorted(unknown)))
    result[mode]={'input_sha256':hashlib.sha256(data).hexdigest(),'wrapper_count':len(actual),
                  'other_compiler_symbols':sorted(compiler),'unexpected':sorted(unknown)}
out=a.out
if out.exists():raise SystemExit('output exists')
out.write_text(json.dumps({'outcome':'passed','scope':'MSVC object definitions only; no whole-program or other-platform claim','results':result},indent=2)+'\n',encoding='utf-8')
print('PASS all defined MSVC external symbols classified')

