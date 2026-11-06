"""Mutate genuine readelf text to test fixed ELF headers and export rules."""
import argparse,re
from pathlib import Path
from verify_aar import check_elf_header,check_elf_symbols

p=argparse.ArgumentParser()
for name in ('header','arm64','arm32'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args()
header=a.header.read_text(encoding='utf-8')
expected=set(re.findall(r'\b(?:dmg_status|void|uint32_t|const\s+char\s*\*)\s*(dmg_[A-Za-z0-9_]+)\s*\(',header))
expected.update('Java_io_github_jichuo1_dexmeguviz_NativeEngine_'+name for name in ('abiVersion','capabilities','nativeOpenRawDex','nativeSnapshotInfo','nativeClose','nativeQueryMethods','nativeOpenRawDexSet','nativeOpenSources','nativeSourceSetInfo','nativeQuerySourceSetMethods','nativeStartMethodJob','nativeJobNext','nativeJobStatus','nativeJobCancel','nativeJobClose','nativeQueryEntities','nativeStartEntityJob','nativeQueryReflectionMethodUses','nativeStartReflectionMethodUsesJob','nativeEntityJobNext','nativeQueryGraph','nativeQueryUseGraph','nativeStartGraphJob','nativeGraphJobNext'))
checks=0
def reject(fn,label):
 global checks
 try:fn()
 except ValueError:checks+=1;return
 raise SystemExit('unexpected acceptance: '+label)
for abi,path,kind,machine in [('arm64-v8a',a.arm64,'ELF64','AArch64'),('armeabi-v7a',a.arm32,'ELF32','ARM')]:
 text=path.read_text(encoding='utf-8')
 check_elf_header(text,abi);exports,_=check_elf_symbols(text,expected,abi)
 if set(exports)!=expected:raise SystemExit('unexpected baseline symbols')
 wrongclass='ELF32' if kind=='ELF64' else 'ELF64'
 for label,old,new in [('class',kind,wrongclass),('endianness','little endian','big endian'),
                       ('type','DYN (Shared object file)','EXEC (Executable file)'),('machine',machine,'WrongMachine')]:
  if old not in text:raise SystemExit('missing source text '+label)
  reject(lambda t=text.replace(old,new,1):check_elf_header(t,abi),abi+'-'+label)
 selected=next(line for line in text.splitlines() if re.search(r'\bFUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+dmg_snapshot_open_sources\s*$',line))
 for label,new in [('object',selected.replace('FUNC','OBJECT',1)),
                   ('weak',selected.replace('GLOBAL','WEAK',1)),
                   ('protected',selected.replace('DEFAULT','PROTECTED',1)),
                   ('absolute',re.sub(r'(DEFAULT\s+)\d+',r'\1ABS',selected,count=1)),
                   ('version',selected.replace('dmg_snapshot_open_sources','dmg_snapshot_open_sources@BAD',1))]:
  reject(lambda t=text.replace(selected,new,1):check_elf_symbols(t,expected,abi),abi+'-'+label)
 reject(lambda:check_elf_symbols(text+'\n'+selected+'\n',expected,abi),abi+'-duplicate')
 reject(lambda:check_elf_symbols(text+'\n 999: 0000 1 FUNC GLOBAL DEFAULT 14 dmg_unexpected\n',expected,abi),abi+'-unexpected')
 reject(lambda:check_elf_symbols(text+'\n 999: 0000 1 FUNC GLOBAL PROTECTED 14 dmg_unexpected\n',expected,abi),abi+'-unexpected-protected')
 print(abi,'real header and',len(exports),'exports accepted')
print('PASS',checks,'readelf text negatives; not mutated ELF binaries')
