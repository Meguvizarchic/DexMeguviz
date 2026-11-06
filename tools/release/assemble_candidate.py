"""Build a local unverified DexMeguviz candidate from explicit pinned inputs."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MIB = 1024 * 1024
MAX_ITEM = 256 * MIB
MAX_TOTAL = 1024 * MIB
FILES = {
    'android_aar': 'android/dexmeguviz.aar',
    'desktop_cli': 'desktop/dexmeguviz.exe',
    'c_header': 'include/dexmeguviz/dexmeguviz.h',
    'notices': 'THIRD_PARTY_NOTICES',
    'miniz_license': 'licenses/miniz.txt',
    'miniz_lock': 'locks/miniz.json',
    'sqlite_notice': 'licenses/sqlite.txt',
    'sqlite_lock': 'locks/sqlite.json',
    'bil_adapter': 'android/dexmeguviz-bil.jar',
    'sample_apk': 'android/sample-debug.apk',
    'parameters_header': 'include/dexmeguviz/method_parameters_v1.h',
    'persistent_header': 'include/dexmeguviz/persistent_cache_v1.h',
    'desktop_core_lib': 'lib/dexmeguviz_core.lib',
    'desktop_miniz_lib': 'lib/dmg_miniz.lib',
    'desktop_cache_lib': 'lib/dmg_persistent_facts.lib',
    'desktop_sql_session': 'desktop/dexmeguviz_sql_session.exe',
    'desktop_cache_sources': 'desktop/dexmeguviz_cache_sources.exe',
}
REQUIRED = {'android_aar', 'desktop_cli', 'c_header', 'notices', 'miniz_license', 'miniz_lock', 'desktop_core_lib', 'desktop_miniz_lib', 'parameters_header'}
HEX = re.compile(r'[0-9a-f]{64}\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}\Z')

class Invalid(ValueError):
    pass

def require(value, message):
    if not value:
        raise Invalid(message)

def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result

def plain(path):
    """Reject every existing symlink/junction along an absolute path."""
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode) and not (getattr(info, 'st_file_attributes', 0) & 0x400),
                'symbolic link or reparse point')
    return path

def inspect(path, expected=None):
    path = plain(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), 'input is not a regular file')
    require(0 <= info.st_size <= MAX_ITEM, 'artifact size limit')
    digest = hashlib.sha256()
    length = 0
    with path.open('rb') as source:
        while True:
            part = source.read(MIB)
            if not part: break
            length += len(part)
            require(length <= MAX_ITEM, 'artifact grew beyond size limit')
            digest.update(part)
    require(length == info.st_size, 'artifact changed while read')
    value = digest.hexdigest()
    if expected is not None: require(value == expected, 'artifact digest mismatch')
    return path, length, value

def load(path):
    path = plain(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= MIB, 'input manifest limit')
    with path.open('rb') as stream: data = stream.read(MIB + 1)
    require(len(data) <= MIB, 'input manifest limit')
    def reject(_): raise Invalid('nonintegral JSON number')
    obj = json.loads(data, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
    require(type(obj) is dict and set(obj) == {'schema_version','project_version','artifacts'}, 'input manifest shape')
    require(type(obj['schema_version']) is int and obj['schema_version'] == 1, 'input manifest version')
    require(type(obj['project_version']) is str and VERSION.fullmatch(obj['project_version']), 'invalid project version')
    items = obj['artifacts']
    require(type(items) is list and len(REQUIRED) <= len(items) <= len(FILES), 'artifact count')
    values, seen = [], set()
    total = 0
    for item in items:
        require(type(item) is dict and set(item) == {'kind','path','sha256','source_build_id'}, 'artifact shape')
        kind = item['kind']
        require(type(kind) is str and kind in FILES and kind not in seen, 'unknown or duplicate kind')
        seen.add(kind)
        for field in ('sha256','source_build_id'):
            require(type(item[field]) is str and HEX.fullmatch(item[field]), 'invalid hash claim')
        require(type(item['path']) is str and '\0' not in item['path'] and Path(item['path']).is_absolute(), 'absolute input path required')
        source, length, digest = inspect(item['path'], item['sha256'])
        total += length
        require(total <= MAX_TOTAL, 'aggregate artifact size limit')
        values.append({'kind':kind,'source':source,'file':FILES[kind],'size':length,'sha256':digest,'source_build_id':item['source_build_id']})
    require(REQUIRED <= seen, 'required artifact missing')
    require(('sqlite_notice' in seen) == ('sqlite_lock' in seen), 'SQLite notices/lock must be paired')
    require('desktop_sql_session' not in seen or 'sqlite_notice' in seen, 'SQL session requires SQLite notices and lock')
    require(('persistent_header' in seen) == ('desktop_cache_lib' in seen), 'persistent C header/library must be paired')
    return path, obj['project_version'], sorted(values, key=lambda x:x['kind'])

def copy_one(item, out):
    destination = out / item['file']
    destination.parent.mkdir(parents=True, exist_ok=True)
    plain(destination.parent)
    digest = hashlib.sha256(); length = 0
    with item['source'].open('rb') as source, destination.open('xb') as target:
        while True:
            part = source.read(MIB)
            if not part: break
            length += len(part)
            require(length <= item['size'], 'source changed during copy')
            target.write(part); digest.update(part)
        target.flush(); os.fsync(target.fileno())
    require(length == item['size'] and digest.hexdigest() == item['sha256'], 'source changed during copy')
    _, copied_size, copied_hash = inspect(destination, item['sha256'])
    require(copied_size == item['size'] and copied_hash == item['sha256'], 'candidate copy mismatch')

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manifest, version, values = load(args.input)
        out = plain(args.out)
        require(not out.exists() and not out.is_symlink(), 'output must not exist')
        require(out.parent.is_dir(), 'output parent must already exist')
        for source in [manifest, *(item['source'] for item in values)]:
            require(out != source and out not in source.parents and source not in out.parents, 'output overlaps input')
        out.mkdir(exist_ok=False)
        for item in values: copy_one(item, out)
        public = [{'kind':v['kind'],'file':v['file'],'size':v['size'],'sha256':v['sha256'],
                   'source_build_id':v['source_build_id']} for v in values]
        metadata = {'schema_version':1,'status':'local_unverified','project_version':version,
                    'source_equivalence_verified':False,'project_license':'pending','artifacts':public}
        encoded = (json.dumps(metadata,ensure_ascii=True,sort_keys=True,indent=2)+'\n').encode('ascii')
        sums = ''.join(v['sha256']+'  '+v['file']+'\n' for v in sorted(public,key=lambda x:x['file'])).encode('ascii')
        for name, data in [('manifest.json',encoded),('SHA256SUMS',sums)]:
            with (out/name).open('xb') as stream:
                stream.write(data);stream.flush();os.fsync(stream.fileno())
        print(json.dumps({'status':'local_unverified','artifacts':len(public),'source_equivalence_verified':False}))
        return 0
    except (Invalid, OSError, ValueError, TypeError, RecursionError, UnicodeError) as error:
        print('candidate assembly failed: '+str(error),file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
