#!/usr/bin/env python3
'''Read-only local candidate verifier.'''

import argparse
import hashlib
import json
import os
import stat
import sys

MIB = 1024 * 1024
MAX_METADATA = MIB
MAX_ARTIFACT = 256 * MIB
MAX_TOTAL = 1024 * MIB
HEX = '0123456789abcdef'
NEWLINE = bytes((10,))
CARRIAGE_RETURN = bytes((13,))

REQUIRED_KINDS = (
    'android_aar',
    'desktop_cli',
    'c_header',
    'notices',
    'miniz_license',
    'miniz_lock',
    'desktop_core_lib',
    'desktop_miniz_lib',
    'parameters_header',
)
KIND_TO_FILE = {
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
MANIFEST_KEYS = {
    'schema_version',
    'status',
    'project_version',
    'source_equivalence_verified',
    'project_license',
    'artifacts',
}
ARTIFACT_KEYS = {
    'kind',
    'file',
    'size',
    'sha256',
    'source_build_id',
}
SQLITE_KINDS = ('sqlite_notice', 'sqlite_lock')
SUCCESS_STATUS = 'integrity_verified_not_authenticated'


class VerificationError(Exception):
    pass


def fail(message):
    raise VerificationError(message)


def is_lower_hex_64(value):
    return (
        type(value) is str
        and len(value) == 64
        and all(ch in HEX for ch in value)
    )


def is_reparse(st):
    attributes = getattr(st, 'st_file_attributes', 0)
    flag = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x00000400)
    return bool(attributes & flag)


def reject_link_or_reparse(path, st):
    if stat.S_ISLNK(st.st_mode):
        fail('symlink rejected: ' + path)
    if is_reparse(st):
        fail('reparse point rejected: ' + path)


def open_readonly_no_follow(path):
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
    no_follow = getattr(os, 'O_NOFOLLOW', 0)
    if no_follow:
        flags |= no_follow
    try:
        return os.open(path, flags)
    except OSError as exc:
        fail('cannot open ' + path + ': ' + str(exc))


def read_bounded(path, limit, label):
    try:
        pre_st = os.lstat(path)
    except OSError as exc:
        fail('cannot stat ' + label + ': ' + str(exc))
    reject_link_or_reparse(path, pre_st)
    if not stat.S_ISREG(pre_st.st_mode):
        fail(label + ' is not a regular file: ' + path)
    if pre_st.st_size > limit:
        fail(label + ' exceeds 1 MiB: ' + path)
    fd = open_readonly_no_follow(path)
    try:
        st = os.fstat(fd)
        reject_link_or_reparse(path, st)
        if not stat.S_ISREG(st.st_mode):
            fail(label + ' is not a regular file: ' + path)
        if st.st_size > limit:
            fail(label + ' exceeds 1 MiB: ' + path)
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b''.join(chunks)
        if len(data) > limit:
            fail(label + ' exceeds 1 MiB: ' + path)
        return data
    finally:
        os.close(fd)


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail('duplicate JSON key: ' + key)
        result[key] = value
    return result


def reject_json_constant(value):
    fail('invalid JSON constant: ' + value)


def load_manifest(data):
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        fail('manifest.json is not valid UTF-8: ' + str(exc))
    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except VerificationError:
        raise
    except ValueError as exc:
        fail('manifest.json is not valid JSON: ' + str(exc))


def require_exact_keys(value, expected, label):
    if type(value) is not dict:
        fail(label + ' must be an object')
    actual = set(value.keys())
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        parts = []
        if missing:
            parts.append('missing ' + ','.join(missing))
        if extra:
            parts.append('extra ' + ','.join(extra))
        fail(label + ' has wrong keys: ' + '; '.join(parts))


def require_string(value, label):
    if type(value) is not str:
        fail(label + ' must be a string')
    return value


def require_int(value, label):
    if type(value) is not int:
        fail(label + ' must be an integer')
    return value


def require_bool(value, label):
    if type(value) is not bool:
        fail(label + ' must be a boolean')
    return value


def validate_manifest(manifest):
    require_exact_keys(manifest, MANIFEST_KEYS, 'manifest')
    schema_version = require_int(manifest['schema_version'], 'manifest.schema_version')
    if schema_version != 1:
        fail('manifest.schema_version must be 1')
    status = require_string(manifest['status'], 'manifest.status')
    if status != 'local_unverified':
        fail('manifest.status must be local_unverified')
    require_string(manifest['project_version'], 'manifest.project_version')
    source_equivalence_verified = require_bool(
        manifest['source_equivalence_verified'],
        'manifest.source_equivalence_verified',
    )
    if source_equivalence_verified is not False:
        fail('manifest.source_equivalence_verified must be false')
    project_license = require_string(
        manifest['project_license'],
        'manifest.project_license',
    )
    if project_license != 'pending':
        fail('manifest.project_license must be pending')
    artifacts = manifest['artifacts']
    if type(artifacts) is not list:
        fail('manifest.artifacts must be an array')
    seen = set()
    kinds = []
    total_size = 0
    normalized = []
    for index, artifact in enumerate(artifacts):
        label = 'manifest.artifacts[' + str(index) + ']'
        require_exact_keys(artifact, ARTIFACT_KEYS, label)
        kind = require_string(artifact['kind'], label + '.kind')
        if kind not in KIND_TO_FILE:
            fail(label + '.kind is not allowed: ' + kind)
        if kind in seen:
            fail('duplicate artifact kind: ' + kind)
        seen.add(kind)
        kinds.append(kind)
        expected_file = KIND_TO_FILE[kind]
        file_value = require_string(artifact['file'], label + '.file')
        if file_value != expected_file:
            fail(label + '.file must be ' + expected_file)
        size = require_int(artifact['size'], label + '.size')
        if size < 0:
            fail(label + '.size must be nonnegative')
        if size > MAX_ARTIFACT:
            fail(label + '.size exceeds 256 MiB')
        total_size += size
        sha256 = require_string(artifact['sha256'], label + '.sha256')
        if not is_lower_hex_64(sha256):
            fail(label + '.sha256 must be 64 lowercase hex characters')
        source_build_id = require_string(
            artifact['source_build_id'],
            label + '.source_build_id',
        )
        if not is_lower_hex_64(source_build_id):
            fail(label + '.source_build_id must be 64 lowercase hex characters')
        normalized.append({
            'kind': kind,
            'file': expected_file,
            'size': size,
            'sha256': sha256,
            'source_build_id': source_build_id,
        })
    if total_size > MAX_TOTAL:
        fail('manifest artifact total exceeds 1 GiB')
    for kind in REQUIRED_KINDS:
        if kind not in seen:
            fail('missing required artifact kind: ' + kind)
    sqlite_present = [kind in seen for kind in SQLITE_KINDS]
    if any(sqlite_present) and not all(sqlite_present):
        fail('sqlite_notice and sqlite_lock must both be present or both absent')
    if 'desktop_sql_session' in seen and 'sqlite_notice' not in seen:
        fail('SQL session requires SQLite notices and lock')
    if ('persistent_header' in seen) != ('desktop_cache_lib' in seen):
        fail('persistent C header/library must both be present or both absent')
    if kinds != sorted(kinds):
        fail('manifest.artifacts must be sorted by kind')
    return normalized


def parse_sha256sums(data, artifacts):
    if not data:
        fail('SHA256SUMS is empty')
    if not data.endswith(NEWLINE):
        fail('SHA256SUMS must end with a newline')
    lines = data.split(NEWLINE)[:-1]
    entries = []
    paths = []
    for index, line in enumerate(lines):
        label = 'SHA256SUMS line ' + str(index + 1)
        if CARRIAGE_RETURN in line:
            fail(label + ' contains a carriage return')
        if len(line) < 67:
            fail(label + ' is too short')
        hash_bytes = line[:64]
        separator = line[64:66]
        path_bytes = line[66:]
        if separator != b'  ':
            fail(label + ' must have two spaces after the hash')
        try:
            hash_value = hash_bytes.decode('ascii')
            path = path_bytes.decode('utf-8')
        except UnicodeDecodeError as exc:
            fail(label + ' is not valid text: ' + str(exc))
        if not is_lower_hex_64(hash_value):
            fail(label + ' hash must be 64 lowercase hex characters')
        if not path:
            fail(label + ' path is empty')
        entries.append((hash_value, path))
        paths.append(path)
    if paths != sorted(paths):
        fail('SHA256SUMS lines must be sorted by path')
    if len(paths) != len(set(paths)):
        fail('SHA256SUMS contains duplicate paths')
    expected = {artifact['file']: artifact['sha256'] for artifact in artifacts}
    if set(paths) != set(expected.keys()):
        missing = sorted(set(expected.keys()) - set(paths))
        extra = sorted(set(paths) - set(expected.keys()))
        parts = []
        if missing:
            parts.append('missing ' + ','.join(missing))
        if extra:
            parts.append('extra ' + ','.join(extra))
        fail('SHA256SUMS paths do not match manifest: ' + '; '.join(parts))
    for hash_value, path in entries:
        if hash_value != expected[path]:
            fail('SHA256SUMS hash mismatch for ' + path)
    expected_bytes = b''.join(
        (expected[path] + '  ' + path).encode('ascii') + NEWLINE
        for path in sorted(expected)
    )
    if data != expected_bytes:
        fail('SHA256SUMS bytes do not match the required exact format')
    return entries


def rel_join(prefix, name):
    if prefix:
        return prefix + '/' + name
    return name


def validate_tree(root, allowed_files):
    root_st = os.lstat(root)
    reject_link_or_reparse(root, root_st)
    if not stat.S_ISDIR(root_st.st_mode):
        fail('candidate directory is not a directory: ' + root)
    allowed_dirs = set()
    for file_path in allowed_files:
        parts = file_path.split('/')
        for index in range(1, len(parts)):
            allowed_dirs.add('/'.join(parts[:index]))
    seen_files = set()
    scanned = 0

    def walk(abs_dir, rel_dir):
        nonlocal scanned
        try:
            entries = []
            with os.scandir(abs_dir) as iterator:
                for entry in iterator:
                    scanned += 1
                    if scanned > 128:
                        fail('candidate entry count exceeds 128')
                    entries.append(entry)
        except OSError as exc:
            fail('cannot read directory ' + abs_dir + ': ' + str(exc))
        for entry in entries:
            rel_path = rel_join(rel_dir, entry.name)
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                fail('cannot stat ' + entry.path + ': ' + str(exc))
            reject_link_or_reparse(entry.path, st)
            if stat.S_ISDIR(st.st_mode):
                if rel_path not in allowed_dirs:
                    fail('extra directory in candidate: ' + rel_path)
                walk(entry.path, rel_path)
            elif stat.S_ISREG(st.st_mode):
                if rel_path not in allowed_files:
                    fail('extra file in candidate: ' + rel_path)
                seen_files.add(rel_path)
            else:
                fail('special file in candidate: ' + rel_path)

    walk(root, '')
    missing = sorted(allowed_files - seen_files)
    if missing:
        fail('missing candidate file(s): ' + ','.join(missing))
    return seen_files


def hash_artifact(path, expected_size, expected_sha256):
    try:
        pre_st = os.lstat(path)
    except OSError as exc:
        fail('cannot stat artifact ' + path + ': ' + str(exc))
    reject_link_or_reparse(path, pre_st)
    if not stat.S_ISREG(pre_st.st_mode):
        fail('artifact is not a regular file: ' + path)
    if pre_st.st_size != expected_size:
        fail(
            'size mismatch for ' + path + ': declared ' + str(expected_size)
            + ', actual ' + str(pre_st.st_size)
        )
    fd = open_readonly_no_follow(path)
    try:
        st = os.fstat(fd)
        reject_link_or_reparse(path, st)
        if not stat.S_ISREG(st.st_mode):
            fail('artifact is not a regular file: ' + path)
        if st.st_size != expected_size:
            fail(
                'size mismatch for ' + path + ': declared ' + str(expected_size)
                + ', actual ' + str(st.st_size)
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size:
                fail('size mismatch for ' + path + ': file grew')
            digest.update(chunk)
        if total != expected_size:
            fail(
                'size mismatch for ' + path + ': declared ' + str(expected_size)
                + ', read ' + str(total)
            )
        actual_sha256 = digest.hexdigest()
        if actual_sha256 != expected_sha256:
            fail('sha256 mismatch for ' + path)
    finally:
        os.close(fd)


def verify_candidate(directory):
    # Reject linked ancestors before walking the tree, not just the leaf itself.
    probe = os.path.abspath(directory)
    while True:
        try:
            ancestor = os.lstat(probe)
        except OSError as exc:
            fail('cannot stat candidate ancestor: ' + str(exc))
        reject_link_or_reparse(probe, ancestor)
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    try:
        root_st = os.lstat(directory)
    except OSError as exc:
        fail('cannot stat candidate directory: ' + str(exc))
    reject_link_or_reparse(directory, root_st)
    if not stat.S_ISDIR(root_st.st_mode):
        fail('candidate path is not a directory: ' + directory)
    manifest_path = os.path.join(directory, 'manifest.json')
    sums_path = os.path.join(directory, 'SHA256SUMS')
    manifest_data = read_bounded(manifest_path, MAX_METADATA, 'manifest.json')
    sums_data = read_bounded(sums_path, MAX_METADATA, 'SHA256SUMS')
    manifest = load_manifest(manifest_data)
    artifacts = validate_manifest(manifest)
    parse_sha256sums(sums_data, artifacts)
    allowed_files = {'manifest.json', 'SHA256SUMS'}
    for artifact in artifacts:
        allowed_files.add(artifact['file'])
    validate_tree(directory, allowed_files)
    for artifact in artifacts:
        artifact_path = os.path.join(directory, *artifact['file'].split('/'))
        hash_artifact(artifact_path, artifact['size'], artifact['sha256'])


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Verify a DexMeguviz local candidate directory.'
    )
    parser.add_argument(
        '--directory',
        required=True,
        help='candidate directory to verify',
    )
    args = parser.parse_args(argv)
    try:
        verify_candidate(args.directory)
    except VerificationError as exc:
        print('verify_candidate: ' + str(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError) as exc:
        print('verify_candidate: ' + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({'status': SUCCESS_STATUS}, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
