"""Conservative Java 17 bytecode declaration comparison for two local JAR/AAR files."""
from __future__ import annotations
import argparse,hashlib,io,json,os,stat,sys,zipfile
from pathlib import Path
from jni_classfile import ClassError,parse

MAX_ARCHIVE=64*1024*1024
MAX_UNPACKED=256*1024*1024
MAX_MEMBER=16*1024*1024
MAX_ENTRIES=20000

def read_bounded(path):
    path=Path(os.path.abspath(path))
    for part in (path,*path.parents):
        info=part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('symbolic link or reparse point')
    with path.open('rb') as f:
        before=os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>MAX_ARCHIVE:raise ValueError('input is not a bounded regular file')
        data=f.read(MAX_ARCHIVE+1);after=os.fstat(f.fileno())
    if len(data)>MAX_ARCHIVE or len(data)!=before.st_size or (before.st_size,before.st_mtime_ns,before.st_ino)!=(after.st_size,after.st_mtime_ns,after.st_ino):raise ValueError('input changed while reading')
    return data

def entries(z):
    all_items=z.infolist()
    if len(all_items)>MAX_ENTRIES:raise ValueError('archive entry count limit')
    seen=set();total=0
    for item in all_items:
        name=item.filename;parts=name.rstrip('/').split('/')
        if not name or item.orig_filename!=name or name.startswith('/') or '\\' in name or ':' in parts[0] or any(p in ('','.','..') for p in parts):raise ValueError('unsafe archive path')
        key=name.rstrip('/')
        if key in seen:raise ValueError('duplicate archive entry')
        seen.add(key)
        mode=item.external_attr>>16;kind=stat.S_IFMT(mode)
        if kind and kind not in (stat.S_IFREG,stat.S_IFDIR):raise ValueError('archive special entry')
        if item.flag_bits&1 or item.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):raise ValueError('unsupported archive entry')
        if item.file_size>MAX_MEMBER:raise ValueError('archive member limit')
        total+=item.file_size
        if total>MAX_UNPACKED:raise ValueError('archive expansion limit')
    return all_items

def load(path,prefix):
    data=read_bounded(path);digest=hashlib.sha256(data).hexdigest()
    with zipfile.ZipFile(io.BytesIO(data)) as outer:
        names=entries(outer);candidates=[i for i in names if i.filename=='classes.jar' and not i.is_dir()]
        if candidates:
            if len(candidates)!=1 or any(i.filename.endswith('.class') for i in names):raise ValueError('ambiguous nested classes.jar and top-level classes')
            content=outer.read(candidates[0]);jar=zipfile.ZipFile(io.BytesIO(content))
        else:jar=zipfile.ZipFile(io.BytesIO(data))
        try:
            result={}
            for item in entries(jar):
                if not item.is_dir() and item.filename.startswith('META-INF/versions/') and item.filename.endswith('.class'):raise ValueError('multi-release classes unsupported')
                if item.is_dir() or not item.filename.startswith(prefix) or not item.filename.endswith('.class'):continue
                info=parse(jar.read(item));expected=item.filename[:-6].encode('utf8')
                if info['name']!=expected:raise ValueError('class identity/path mismatch')
                result[item.filename]=info
        finally:jar.close()
    if not result:raise ValueError('no matching classes')
    return digest,result

def compare(old,new):
    issues=[]
    def issue(name,kind,detail):issues.append({'class':name[:-6], 'kind':kind,'detail':detail})
    def visibility(flags):return 2 if flags&1 else 1 if flags&4 else 0
    def members(values):
        result={}
        for item in values:
            key=(item['name'],item['descriptor'])
            if key in result:raise ValueError('duplicate member signature')
            result[key]=item['access']
        return result
    for name,base in old.items():
        if not(base['flags']&1):continue
        if name not in new:issue(name,'class_missing','public class missing');continue
        current=new[name];a,b=base['flags'],current['flags']
        if not(b&1):issue(name,'class_visibility','public visibility removed')
        if bool(a&0x200)!=bool(b&0x200):issue(name,'class_kind','class/interface changed')
        if not(a&0x10) and b&0x10:issue(name,'class_final','class newly final')
        if not(a&0x400) and b&0x400:issue(name,'class_abstract','class newly abstract')
        if base['superclass']!=current['superclass']:issue(name,'superclass','direct superclass changed; review hierarchy')
        for label in ('fields','methods'):
            newer=members(current[label])
            for key,flags in members(base[label]).items():
                if visibility(flags)==0 or key[0]==b'<clinit>':continue
                desc=key[0].decode('utf8','backslashreplace')+' '+key[1].decode('utf8','backslashreplace')
                if key not in newer:issue(name,label+'_missing',desc);continue
                nf=newer[key]
                if visibility(nf)<visibility(flags):issue(name,label+'_visibility',desc)
                if bool(flags&8)!=bool(nf&8):issue(name,label+'_static',desc)
                if not(flags&0x10) and nf&0x10:issue(name,label+'_final',desc)
                if label=='methods' and not(flags&0x400) and nf&0x400:issue(name,'method_abstract',desc)
    return issues

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--old',type=Path,required=True);ap.add_argument('--new',type=Path,required=True);ap.add_argument('--prefix',default='io/github/jichuo1/dexmeguviz/');a=ap.parse_args()
    if not a.prefix or a.prefix.startswith('/') or '\\' in a.prefix or '..' in a.prefix.split('/'):raise ValueError('invalid prefix')
    old_hash,old=load(a.old,a.prefix);new_hash,new=load(a.new,a.prefix);issues=compare(old,new)
    print(json.dumps({'status':'detected_issues' if issues else 'no_detected_declaration_regressions','old_sha256':old_hash,'new_sha256':new_hash,'old_classes':len(old),'new_classes':len(new),'issues':issues,'scope':'declared public classes and public/protected members in Java 17 classfiles; conservative superclass changes','limitations':['No Kotlin metadata, interfaces, constant inlining, reflection, generics, resources, native ABI, behavior or device validation.','May flag compatible member moves to a superclass; nested visibility and inherited API require further review.','No detected regressions is not a complete binary compatibility guarantee.']},indent=2))
    return 1 if issues else 0
if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,ClassError,zipfile.BadZipFile,RuntimeError,OverflowError) as error:
        print(json.dumps({'status':'invalid_or_unsupported','reason':str(error)}),file=sys.stderr);sys.exit(2)
