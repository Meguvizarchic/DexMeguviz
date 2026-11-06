"""Check MSVC object symbol text, not a complete linker or platform proof."""
import argparse
import re
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--private',required=True,type=Path)
p.add_argument('--adapter',required=True,type=Path)
p.add_argument('--test-build',action='store_true')
a=p.parse_args()
private=a.private.read_text(encoding='utf-8',errors='replace')
adapter=a.adapter.read_text(encoding='utf-8',errors='replace')
rx=re.compile(r'^.*?\b(?:SECT\w+|UNDEF)\b.*?\bExternal\b\s+\|\s+(\S+)',re.M)
private_symbols=rx.findall(private);adapter_symbols=rx.findall(adapter)
for label,symbols in [('private',private_symbols),('adapter',adapter_symbols)]:
    unexpected=[s for s in symbols if re.match(r'^_?sqlite3(?:_|[A-Z])',s)]
    if unexpected:raise SystemExit(label+' has external SQLite symbols: '+repr(unexpected))
names=('bind_parameter_count','bind_int64','bind_null','bind_text','close','column_bytes','column_count','column_int64',
       'column_text','column_type','context_db_handle','create_module_v2','declare_vtab','finalize','limit','open_v2',
       'prepare_v2','reset','clear_bindings','stmt_status','progress_handler','result_error_toobig','result_error_nomem','result_error_code','result_int64','result_null','result_text',
       'set_authorizer','step','stmt_readonly','stricmp','value_type','value_int64','vtab_in','vtab_in_first','vtab_in_next','configure_heap_limit','heap_snapshot')
expected={'dmg_private_sqlite3_'+n for n in names}
if a.test_build:expected|={'dmg_private_sqlite3_test_config_log','dmg_private_sqlite3_test_exec','dmg_private_sqlite3_test_default_vfs_is'}
actual={s for s in private_symbols if s.startswith('dmg_private_sqlite3_')}
if actual!=expected:raise SystemExit('private wrapper symbol mismatch: '+repr(actual^expected))
adapter_wrappers={s for s in adapter_symbols if s.startswith('dmg_private_sqlite3_')}
if adapter_wrappers!=expected:raise SystemExit('adapter wrapper reference mismatch: '+repr(adapter_wrappers^expected))
print('PASS',len(expected),'private wrapper symbols and no external sqlite3 symbols in either object')

