#!/usr/bin/env python3
"""Read-only, bounded marker scan of an Android SDK AAR and Gradle report."""
import argparse
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import zipfile
import zlib

MAX_AAR = 64 * 1024 * 1024
MAX_REPORT = 16 * 1024 * 1024
MARKERS = (b'dexkit', 'dexkit'.encode('utf-16le'), 'dexkit'.encode('utf-16be'))

def fail(message):
    raise ValueError(message)

def input_bytes(path, limit):
    path = os.path.abspath(path)
    current = path
    while True:
        s = os.lstat(current)
        if stat.S_ISLNK(s.st_mode) or getattr(s, 'st_file_attributes', 0) & 0x400:
            fail('input path contains a link or reparse point')
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    with open(path, 'rb') as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            fail('input is not a regular file or exceeds size limit')
        data = f.read(limit + 1)
        after = os.fstat(f.fileno())
        if len(data) > limit or len(data) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            fail('input changed during read or exceeds size limit')
    return data

def digest(data):
    return hashlib.sha256(data).hexdigest()

def verify_hash(data, expected, name):
    actual = digest(data)
    if expected and (not re.fullmatch(r'[0-9a-fA-F]{64}', expected) or actual != expected.lower()):
        fail(name + ' SHA-256 mismatch or invalid expected hash')
    return actual

def safe_entries(z, count_limit, total_limit, member_limit):
    entries = z.infolist()
    if len(entries) > count_limit:
        fail('ZIP entry count exceeds limit')
    seen = set()
    total = 0
    for i in entries:
        n = i.filename
        parts = n.rstrip('/').split('/')
        if not n or i.orig_filename != n or n.startswith('/') or '\\' in n or any(p in ('', '.', '..') for p in parts) or ':' in parts[0]:
            fail('unsafe ZIP entry path')
        normalized = n.rstrip('/')
        if normalized in seen:
            fail('duplicate ZIP entry')
        seen.add(normalized)
        mode = i.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if kind and kind not in (stat.S_IFREG, stat.S_IFDIR):
            fail('ZIP link or special entry')
        if i.flag_bits & 1 or i.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            fail('encrypted or unsupported ZIP entry')
        if i.file_size > member_limit:
            fail('ZIP member exceeds limit')
        total += i.file_size
        if total > total_limit:
            fail('ZIP inflated size exceeds limit')
    return entries

def scan_bytes(data, surface, findings):
    lower = data.lower()
    for marker in MARKERS:
        pos = lower.find(marker)
        if pos >= 0:
            findings.append({'surface': surface, 'encoding': ('ascii' if marker == MARKERS[0] else 'utf16le' if marker == MARKERS[1] else 'utf16be'), 'offset': pos})

def scan_jar(data, label, findings):
    classes = 0
    with zipfile.ZipFile(io.BytesIO(data)) as jar:
        for item in safe_entries(jar, 4096, 64 * 1024 * 1024, 8 * 1024 * 1024):
            scan_bytes(item.filename.encode('utf-8'), label + ':entry-name', findings)
            if item.is_dir():
                continue
            if item.filename.lower().endswith(('.jar', '.aar', '.zip', '.dex', '.so', '.dll', '.dylib')):
                fail('unsupported nested binary container in JAR')
            raw = jar.read(item)
            if item.filename.endswith('.class'):
                classes += 1
                if not raw.startswith(b'\xca\xfe\xba\xbe'):
                    fail('invalid class magic')
            scan_bytes(raw, label + ':' + item.filename, findings)
    return classes

def scan_aar(data, required_abis, findings):
    classes = 0
    jars = []
    native = []
    with zipfile.ZipFile(io.BytesIO(data)) as aar:
        entries = safe_entries(aar, 4096, 256 * 1024 * 1024, 64 * 1024 * 1024)
        if sum(i.filename == 'classes.jar' and not i.is_dir() for i in entries) != 1:
            fail('AAR must contain exactly one classes.jar')
        for item in entries:
            scan_bytes(item.filename.encode('utf-8'), 'aar:entry-name', findings)
            if item.is_dir():
                continue
            raw = aar.read(item)  # verifies CRC even for payloads outside inspected code surfaces
            name = item.filename
            scan_bytes(raw, 'aar:' + name, findings)
            if name == 'classes.jar' or (name.startswith('libs/') and name.lower().endswith('.jar')):
                if len(raw) > 32 * 1024 * 1024:
                    fail('embedded JAR exceeds size limit')
                jars.append(name)
                classes += scan_jar(raw, name, findings)
            elif name.lower().endswith(('.jar', '.aar', '.dex', '.zip')):
                fail('unsupported code container in AAR')
            if name.startswith('jni/') and name.endswith('.so'):
                m = re.fullmatch(r'jni/([A-Za-z0-9_.-]+)/([^/]+\.so)', name)
                if not m or len(raw) < 20 or raw[:4] != b'\x7fELF' or raw[4] not in (1, 2) or raw[5] not in (1, 2):
                    fail('invalid JNI native library path or ELF header')
                machine = struct.unpack(('<' if raw[5] == 1 else '>') + 'H', raw[18:20])[0]
                known = {'arm64-v8a': (2, 183), 'armeabi-v7a': (1, 40), 'x86': (1, 3), 'x86_64': (2, 62)}
                if m.group(1) in known and (raw[4], machine) != known[m.group(1)]:
                    fail('JNI ABI does not match ELF header')
                native.append({'path': name, 'abi': m.group(1), 'elf_machine': machine, 'sha256': digest(raw)})
            elif name.lower().endswith('.so'):
                fail('native library outside supported JNI location')
    if not classes or not native:
        fail('AAR must contain at least one class and one JNI library')
    if set(required_abis) - {n['abi'] for n in native}:
        fail('required ABI missing')
    return jars, classes, native

def check_report(data, findings):
    report = data.decode('utf-8-sig')
    if '\x00' in report or re.search(r'(?im)^\s*(?:BUILD FAILED|.*\bFAILED\b)', report):
        fail('runtime report indicates failure or malformed text')
    lines = report.splitlines()
    headers = [i for i, line in enumerate(lines) if re.match(r'^releaseRuntimeClasspath\s+-\s+', line)]
    if len(headers) != 1 or not any(re.match(r'^BUILD SUCCESSFUL\b', line) for line in lines):
        fail('runtime report lacks a unique releaseRuntimeClasspath and successful build')
    section = []
    for line in lines[headers[0] + 1:]:
        if not line.strip():
            if section:
                break
            continue
        section.append(line)
    if not section:
        fail('runtime dependency section missing')
    if section != ['No dependencies']:
        for line in section:
            if not re.match(r'^\s*(?:[|\\+ ]*---\s+\S|[| ]+\S)', line):
                fail('unsupported runtime dependency section format')
    scan_bytes(data, 'runtime-report', findings)
    return 'empty' if section == ['No dependencies'] else 'dependency-tree'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--aar', required=True)
    parser.add_argument('--runtime-report', required=True)
    parser.add_argument('--expected-aar-sha256')
    parser.add_argument('--expected-report-sha256')
    parser.add_argument('--require-abi', action='append', default=[])
    args = parser.parse_args()
    findings = []
    aar = input_bytes(args.aar, MAX_AAR)
    report = input_bytes(args.runtime_report, MAX_REPORT)
    ah = verify_hash(aar, args.expected_aar_sha256, 'AAR')
    rh = verify_hash(report, args.expected_report_sha256, 'runtime report')
    jars, classes, native = scan_aar(aar, args.require_abi, findings)
    report_type = check_report(report, findings)
    result = {'status': 'marker_found' if findings else 'no_marker_in_inspected_surfaces', 'aar_sha256': ah, 'runtime_report_sha256': rh, 'embedded_jars': jars, 'class_count': classes, 'native_libraries': native, 'runtime_report_section': report_type, 'findings': findings, 'scope': 'ASCII and UTF-16 DexKit marker in AAR entry names and bytes, nested JAR entries and bytes, and complete runtime report', 'limitations': ['Report provenance and relationship to AAR are not authenticated.', 'Renamed, obfuscated, dynamically loaded or external code is not ruled out.', 'ELF and class headers are checked, not fully verified.']}
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 1 if findings else 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, UnicodeError, zipfile.BadZipFile, zlib.error, RuntimeError, EOFError, OverflowError) as exc:
        print(json.dumps({'status': 'invalid_or_unsupported', 'reason': str(exc)}, ensure_ascii=True), file=sys.stderr)
        sys.exit(2)
