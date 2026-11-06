#!/usr/bin/env python3
"""Compare static DEX declarations and references in two explicit input sets.

This consumer invokes the local DexMeguviz CLI without a shell. It performs
no runtime resolution and reports observed multiplicities, never guessed row
pairings. A source set is incomplete unless the caller explicitly declares it.
"""
import argparse
import collections
import contextlib
import hashlib
import json
import os
import re
from pathlib import Path
import struct
import subprocess
import zipfile
import zlib
import sys
import tempfile
import stat

RELATIONS = ('class_defs', 'type_refs', 'field_defs', 'field_refs', 'method_defs', 'method_refs')
KINDS = {'class_defs': 'class', 'type_refs': 'class', 'field_defs': 'field',
         'field_refs': 'field', 'method_defs': 'method', 'method_refs': 'method'}

class DiffError(Exception):
    pass

def check(condition, message):
    if not condition:
        raise DiffError(message)

def output_target(path, protected):
    """Resolve the parent only; never follow an existing output link."""
    target = path.parent.resolve(strict=True) / path.name
    check(path.name not in ('', '.', '..') and target.parent.is_dir(), 'invalid output path')
    check(all(target != item for item in protected), 'output aliases an input or executable')
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return target
    check(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode) and
          not (getattr(metadata, 'st_file_attributes', 0) & 0x400), 'output must be a regular file, not a link')
    check(not any(os.path.samefile(target, item) for item in protected), 'output aliases an input or executable')
    return target

def publish_output(target, data, protected):
    """Write in the destination directory and atomically replace only on success."""
    fd, name = tempfile.mkstemp(prefix='.' + target.name + '.', suffix='.tmp', dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        check(output_target(target, protected) == target, 'output target changed')
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

def file_sha(path, max_bytes=None):
    h = hashlib.sha256()
    consumed = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            consumed += len(block)
            if max_bytes is not None and consumed > max_bytes:
                raise DiffError('input exceeds configured byte limit')
            h.update(block)
    return h.hexdigest()

def key_for(relation, row):
    kind = KINDS[relation]
    fields = ('type_descriptor',) if kind == 'class' else ('owner', 'name', 'type_descriptor' if kind == 'field' else 'prototype')
    values = tuple(row.get(field) for field in fields)
    check(all(type(value) is str for value in values), 'missing or invalid symbol text')
    return (kind, *values)

def entity_record(row, sources, relation):
    check(isinstance(row, dict) and row.get('relation') == relation, 'wrong entity relation')
    s = row.get('source_index'); local = row.get('local_index'); ref = row.get('reference_index')
    check(type(s) is int and 0 <= s < len(sources) and type(local) is int and 0 <= local <= 0xffffffff and type(ref) is int and 0 <= ref <= 0xffffffff, 'invalid local identity')
    origin = sources[s]
    check(type(row.get('input_index')) is int and row['input_index'] == origin['input_index'] and
          all(row.get(field) == origin.get(field) for field in ('source_sha256', 'content_id', 'occurrence_id', 'logical_dex_id')),
          'candidate origin mismatch')
    check(type(row.get('record_offset')) is int and row['record_offset'] >= 0 and type(row.get('has_local_definition')) is bool,
          'invalid definition metadata')
    definition_offset = row.get('definition_offset')
    check((definition_offset is None and not row['has_local_definition']) or
          (type(definition_offset) is int and definition_offset >= 0 and row['has_local_definition']), 'invalid definition offset')
    flags = row.get('access_flags'); code = row.get('code_offset')
    check(flags is None or (type(flags) is int and 0 <= flags <= 0xffffffff), 'invalid access flags')
    check(code is None or (type(code) is int and 0 <= code <= 0xffffffff), 'invalid code offset')
    if relation.endswith('_defs'):
        check(row['has_local_definition'] and flags is not None, 'definition missing static flags')
    if relation == 'method_defs':
        check(code is not None, 'method definition missing code status')
    return {'source_index': s, 'input_index': row['input_index'], 'local_index': local,
            'reference_index': ref, 'record_offset': row['record_offset'],
            'occurrence_id': row['occurrence_id'], 'source_sha256': row['source_sha256'],
            'has_local_definition': row['has_local_definition'], 'definition_offset': definition_offset,
            'access_flags': flags, 'code_offset': code, 'has_code': None if code is None else code != 0}

def source_set(exe, exe_sha, paths, complete, max_results, max_work, budget_mib, input_mib, code_digest, code_max_handler_items, retained=None):
    byte_limit = input_mib * 1024 * 1024
    check(sum(path.stat().st_size for path, _ in paths) <= byte_limit, 'inputs exceed configured byte limit')
    before = [file_sha(path, byte_limit) for path, _ in paths]
    groups = collections.defaultdict(lambda: {'definitions': [], 'references': []})
    sources0 = inputs0 = snapshot = None
    with (contextlib.nullcontext(retained) if retained is not None else tempfile.TemporaryDirectory(prefix='dexmeguviz-diff-')) as tmp:
        for relation in RELATIONS:
            query = Path(tmp) / (relation + '.query.json')
            document = {'schema_version': 1, 'relation': {'op': 'scan', 'relation': relation},
                        'intent': 'enumerate', 'max_results': max_results, 'max_work': max_work}
            with query.open('x', encoding='ascii') as stream:stream.write(json.dumps(document, separators=(',', ':')))
            cmd = [str(exe), 'query', str(paths[0][0]), '--query', str(query), '--json',
                   '--budget-mib', str(budget_mib), '--max-input-mib', str(input_mib)]
            for path, resource in paths[1:]:
                cmd += ['--resource-source' if resource else '--source', str(path)]
            if not complete:
                cmd += ['--scope-incomplete']
            try:
                run = subprocess.run(cmd, capture_output=True, timeout=120)
            except subprocess.TimeoutExpired as error:
                raise DiffError('CLI timed out while scanning ' + relation) from error
            if retained is not None:
                for suffix,data in (('.stdout.json',run.stdout),('.stderr.log',run.stderr),('.command.json',json.dumps({'argv':cmd,'exit':run.returncode},ensure_ascii=True).encode('ascii'))):
                    with (Path(tmp)/(relation+suffix)).open('xb') as saved:saved.write(data)
            if run.returncode != 0:
                detail = run.stderr.decode('utf-8', errors='replace')[:4096].strip()
                if len(run.stdout) <= 8 * 1024 * 1024:
                    try:
                        failure = json.loads(run.stdout)
                        if isinstance(failure, dict):
                            status, reason = failure.get('execution_status'), failure.get('reason')
                            if type(status) is str and type(reason) is str:
                                detail = status + '/' + reason + (': ' + detail if detail else '')
                    except (UnicodeError, ValueError):
                        pass
                raise DiffError('CLI scan failed for ' + relation + ' (exit ' + str(run.returncode) + '): ' + detail)
            check(len(run.stdout) <= 8 * 1024 * 1024, 'CLI output exceeds bound')
            try:
                data = json.loads(run.stdout)
            except (UnicodeError, ValueError) as error:
                raise DiffError('invalid CLI JSON for ' + relation) from error
            check(isinstance(data, dict) and data.get('profile') == 'dex-query-relational-v3' and
                  data.get('execution_status') == 'Complete' and data.get('relation') == relation, 'incomplete or wrong query result')
            expected_coverage = 'Complete' if complete else 'Partial'
            check(data.get('coverage') == expected_coverage and type(data.get('unknown_rows')) is int and data['unknown_rows'] == 0,
                  'unexpected coverage or unknown rows')
            sources = data.get('sources'); inputs = data.get('inputs'); sid = data.get('snapshot_id')
            check(isinstance(sources, list) and isinstance(inputs, list) and len(inputs) == len(paths) and type(sid) is str, 'invalid source metadata')
            check(type(data.get('source_count')) is int and data['source_count'] == len(sources) and
                  type(data.get('input_count')) is int and data['input_count'] == len(inputs), 'source count mismatch')
            scope = data.get('query_scope')
            check(isinstance(scope, dict) and scope.get('complete') is complete and scope.get('explicit') is False and
                  scope.get('sources') == list(range(len(sources))) and
                  all(type(index) is int for index in scope.get('sources', [])), 'scope mismatch')
            for i, entry in enumerate(inputs):
                check(isinstance(entry, dict), 'invalid input metadata')
                check(type(entry.get('input_index')) is int and entry['input_index'] == i and entry.get('source_sha256') == before[i], 'input identity mismatch')
            for i, entry in enumerate(sources):
                check(isinstance(entry, dict) and all(type(entry.get(field)) is str and entry[field] for field in
                      ('source_sha256', 'content_id', 'occurrence_id', 'logical_dex_id')), 'invalid source identity fields')
                check(type(entry.get('source_index')) is int and entry['source_index'] == i and type(entry.get('input_index')) is int and
                      0 <= entry['input_index'] < len(inputs), 'source identity mismatch')
                check(entry.get('snapshot_id') == sid and re.fullmatch(r'[0-9a-f]{64}', entry['source_sha256']) is not None,
                      'source digest or snapshot mismatch')
                parent = inputs[entry['input_index']]
                if parent.get('format') == 'RawDex':
                    check(entry['source_sha256'] == parent['source_sha256'] and not entry.get('archive_sha256'), 'raw source/input digest mismatch')
                elif parent.get('format') == 'Apk':
                    check(entry.get('archive_sha256') == parent['source_sha256'] and type(entry.get('archive_entry_name')) is str and
                          type(entry.get('archive_entry_index')) is int and entry['archive_entry_index'] >= 0, 'archive source/input mismatch')
                else:
                    raise DiffError('unknown input format')
            normalized = [{k: v for k, v in source.items() if k != 'local_scope'} for source in sources]
            if snapshot is None:
                snapshot, sources0, inputs0 = sid, normalized, inputs
            else:
                check(sid == snapshot and normalized == sources0 and inputs == inputs0, 'source snapshot changed between queries')
            rows = data.get('candidates'); total = data.get('total_rows'); visited = data.get('visited_rows')
            check(isinstance(rows, list) and type(total) is int and type(visited) is int and
                  total == visited == len(rows), 'scan did not enumerate every row')
            seen = set()
            for row in rows:
                key = key_for(relation, row)
                record = entity_record(row, sources, relation)
                check(row.get('snapshot_id') == sid, 'candidate snapshot mismatch')
                identity = (record['source_index'], record['local_index'])
                check(identity not in seen, 'duplicate source-local entity'); seen.add(identity)
                group = groups[key]
                group['definitions' if relation.endswith('_defs') else 'references'].append(record)
        if code_digest:
            _add_code_digests(groups, paths, sources0, inputs0, byte_limit, code_max_handler_items)
        check([file_sha(path, byte_limit) for path, _ in paths] == before, 'input bytes changed during scans')
    check(file_sha(exe) == exe_sha, 'CLI executable changed during scans')
    return {'snapshot_id': snapshot, 'scope_complete': complete, 'inputs': inputs0, 'sources': sources0, 'groups': groups}

def _leb32(data, cursor, signed=False):
    start = cursor
    result = 0
    for index in range(5):
        check(cursor < len(data), 'truncated code handler LEB')
        value = data[cursor]; cursor += 1
        if index == 4:
            if signed:
                check(value <= 7 or 0x78 <= value <= 0x7f, 'signed code handler LEB overflow')
            else:
                check(value <= 0x0f, 'unsigned code handler LEB overflow')
        result |= (value & 0x7f) << (index * 7)
        if value < 0x80:
            if signed and value & 0x40:
                result |= -1 << ((index + 1) * 7)
            return result, cursor
    raise DiffError('unterminated code handler LEB at ' + str(start))

def _code_item_digest(data, offset, work):
    check(type(offset) is int and offset > 0 and offset % 4 == 0 and offset <= len(data) - 16,
          'invalid code item offset')
    registers, incoming, outgoing, tries, debug_offset, units = struct.unpack_from('<HHHHII', data, offset)
    check(incoming <= registers and units > 0 and units <= (len(data) - offset - 16) // 2,
          'invalid code item instruction bounds')
    cursor = offset + 16 + units * 2
    if tries:
        cursor = (cursor + 3) & ~3
        check(cursor <= len(data) and tries <= (len(data) - cursor) // 8, 'invalid code try table bounds')
        cursor += tries * 8
        handlers, cursor = _leb32(data, cursor)
        check(handlers > 0 and handlers <= (len(data) - cursor) // 2, 'invalid code handler count')
        check(handlers <= work[0], 'code handler work limit exceeded'); work[0] -= handlers
        for _ in range(handlers):
            count, cursor = _leb32(data, cursor, signed=True)
            pairs = abs(count)
            check(pairs <= (len(data) - cursor) // 2 and pairs <= work[0], 'code handler work limit exceeded')
            work[0] -= pairs
            for _ in range(pairs):
                _, cursor = _leb32(data, cursor)
                _, cursor = _leb32(data, cursor)
            if count <= 0:
                _, cursor = _leb32(data, cursor)
    # debug_info_off is a relocation, not part of this raw code envelope.
    h = hashlib.sha256(); h.update(b'DexMeguviz:raw-code-item:v1\0')
    h.update(memoryview(data)[offset:offset + 8]); h.update(bytes(4))
    h.update(memoryview(data)[offset + 12:cursor])
    return 'sha256:raw-code-item:v1:' + h.hexdigest()

def _read_source_bytes(path, source, parent, byte_limit):
    expected = source.get('source_bytes')
    check(type(expected) is int and 0 <= expected <= byte_limit, 'DEX source exceeds configured byte limit')
    try:
        if parent.get('format') == 'RawDex':
            with path.open('rb') as stream:
                data = stream.read(expected + 1)
        else:
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist(); index = source['archive_entry_index']
                check(index < len(entries), 'archive entry index exceeds directory')
                entry = entries[index]
                check(entry.filename == source['archive_entry_name'] and entry.file_size == expected,
                      'archive entry identity or size mismatch')
                with archive.open(entry) as stream:
                    data = stream.read(expected + 1)
    except (zipfile.BadZipFile, RuntimeError, EOFError, OSError, zlib.error) as error:
        raise DiffError('cannot read verified DEX source: ' + str(error)) from error
    check(len(data) == expected and hashlib.sha256(data).hexdigest() == source['source_sha256'],
          'DEX source bytes differ from snapshot')
    check(len(data) >= 8 and data[:4] == b'dex\n' and data[4:7] in (b'035', b'037', b'038', b'039', b'040') and data[7] == 0,
          'unsupported DEX source for code fingerprint')
    return data

def _add_code_digests(groups, paths, sources, inputs, byte_limit, max_handler_items):
    # Load only sources with code-bearing methods, one logical DEX at a time.
    by_source = collections.defaultdict(list)
    for key, group in groups.items():
        if key[0] != 'method':
            continue
        for row in group['definitions']:
            row['code_sha256'] = None
            if row['has_code']:
                by_source[row['source_index']].append(row)
    check(all(type(source.get('source_bytes')) is int and 0 <= source['source_bytes'] <= byte_limit for source in sources),
          'invalid expanded DEX byte count')
    check(sum(source['source_bytes'] for source in sources) <= byte_limit, 'expanded DEX exceeds configured byte limit')
    work = [max_handler_items]
    for source_index, rows in by_source.items():
        source = sources[source_index]; parent = inputs[source['input_index']]
        data = _read_source_bytes(paths[source['input_index']][0], source, parent, byte_limit)
        cache = {}
        for row in rows:
            offset = row['code_offset']
            if offset not in cache:
                cache[offset] = _code_item_digest(data, offset, work)
            row['code_sha256'] = cache[offset]

def side_summary(group, complete):
    definitions = group['definitions']; references = group['references']
    count = len(definitions)
    resolution = ('one_observed_definition' if count == 1 else 'multiple_observed_definitions' if count > 1 else 'no_observed_definition')
    return {'definition_count': count, 'reference_count': len(references),
            'local_definition_count': sum(x['has_local_definition'] for x in references),
            'observed_resolution': resolution, 'scope_complete': complete,
            'definitions': definitions, 'references': references}

def annotate_reference_candidates(side):
    """Report exact-symbol static candidates; never select a runtime target."""
    definitions = side['definitions']
    local_by_source = {}
    for row in definitions:
        source = row['source_index']
        check(source not in local_by_source, 'duplicate same-symbol definition within one source')
        local_by_source[source] = row
    buckets = collections.Counter()
    complete = side['scope_complete']
    for row in side['references']:
        local = local_by_source.get(row['source_index'])
        check(bool(local) == row['has_local_definition'], 'reference/local definition disagreement')
        if local is not None:
            check(local['reference_index'] == row['reference_index'] and
                  local['definition_offset'] == row['definition_offset'],
                  'reference/local definition identity disagreement')
        other = len(definitions) - (1 if local is not None else 0)
        bucket = (local is not None, other)
        buckets[bucket] += 1
        row['static_candidates'] = {
            'local_definition': 'observed' if local is not None else 'not_observed',
            'other_source_definition_count': other,
            'other_source_state': 'none_observed' if other == 0 else 'one_observed' if other == 1 else 'multiple_observed',
            'candidate_count_is_lower_bound': not complete,
            'runtime_resolution': 'not_evaluated',
        }
    return [{'local_definition_observed': local, 'other_source_definition_count': other,
             'reference_count': count} for (local, other), count in sorted(buckets.items())]

def occurrence_changes(before, after):
    """Set difference of exact occurrence IDs only; not cross-version pairing."""
    def indexed(sources):
        out = {}
        for source in sources:
            ident = source['occurrence_id']
            check(ident not in out, 'duplicate occurrence identity in snapshot')
            out[ident] = {'occurrence_id': ident, 'source_index': source['source_index'],
                          'input_index': source['input_index'], 'source_sha256': source['source_sha256']}
        return out
    left, right = indexed(before), indexed(after)
    return {'comparison': 'exact_occurrence_id_only_no_cross_version_pairing',
            'only_before': [left[x['occurrence_id']] for x in before if x['occurrence_id'] not in right],
            'only_after': [right[x['occurrence_id']] for x in after if x['occurrence_id'] not in left],
            'present_in_both': [x['occurrence_id'] for x in before if x['occurrence_id'] in right]}

def main(argv=None):
    parser = argparse.ArgumentParser(description='Compare static symbols in two explicit DEX/APK input sets')
    parser.add_argument('--exe', required=True, type=Path)
    parser.add_argument('--before', required=True, nargs='+', type=Path)
    parser.add_argument('--after', required=True, nargs='+', type=Path)
    parser.add_argument('--before-resource', action='append', type=Path, default=[])
    parser.add_argument('--after-resource', action='append', type=Path, default=[])
    parser.add_argument('--before-complete', action='store_true')
    parser.add_argument('--after-complete', action='store_true')
    parser.add_argument('--max-results', type=int, default=4096)
    parser.add_argument('--max-work', type=int, default=100000000)
    parser.add_argument('--output', type=Path, help='atomically publish complete JSON to this file instead of stdout')
    parser.add_argument('--budget-mib', type=int, default=512)
    parser.add_argument('--max-input-mib', type=int, default=512)
    parser.add_argument('--code-digest', action='store_true', help='compare raw code-item fingerprints (not runtime semantics)')
    parser.add_argument('--reference-candidates', action='store_true', help='report exact-symbol static reference candidates across source occurrences')
    parser.add_argument('--code-max-handler-items', type=int, default=1000000)
    parser.add_argument('--workdir', type=Path, help='new retained scan workspace; no automatic cleanup inside it')
    args = parser.parse_args(argv)
    try:
        exe = args.exe.resolve(strict=True)
        before = [(p.resolve(strict=True), False) for p in args.before] + [(p.resolve(strict=True), True) for p in args.before_resource]
        after = [(p.resolve(strict=True), False) for p in args.after] + [(p.resolve(strict=True), True) for p in args.after_resource]
        check(exe.is_file() and all(p.is_file() for p, _ in before + after), 'input must be a file')
        protected = {exe, Path(__file__).resolve(strict=True), *(p for p, _ in before + after)}
        target = output_target(args.output, protected) if args.output is not None else None
        check(1 <= len(before) <= 64 and 1 <= len(after) <= 64, 'source count out of range')
        check(1 <= args.max_results <= 100000 and 1 <= args.max_work <= 100000000 and
              1 <= args.budget_mib <= 4096 and 1 <= args.max_input_mib <= 4096 and 1 <= args.code_max_handler_items <= 10000000, 'invalid limits')
        workspace=None
        if args.workdir is not None:
            workspace=Path(os.path.abspath(args.workdir))
            for parent in [*workspace.parents,workspace]:
                try:entry=parent.lstat()
                except FileNotFoundError:continue
                check(not stat.S_ISLNK(entry.st_mode) and not (getattr(entry,'st_file_attributes',0)&0x400),'workdir reparse point rejected')
            check(not workspace.exists() and workspace.parent.is_dir(),'workdir must be a new direct directory')
            workspace.mkdir();(workspace/'before').mkdir();(workspace/'after').mkdir()
        exe_sha = file_sha(exe)
        left = source_set(exe, exe_sha, before, args.before_complete, args.max_results, args.max_work, args.budget_mib, args.max_input_mib, args.code_digest, args.code_max_handler_items, workspace/'before' if workspace else None)
        right = source_set(exe, exe_sha, after, args.after_complete, args.max_results, args.max_work, args.budget_mib, args.max_input_mib, args.code_digest, args.code_max_handler_items, workspace/'after' if workspace else None)
        # Both sides must still be the same bytes after all twelve scans.
        # Input locks are not held: a transient change restored between checks
        # cannot be detected and remains outside this read-only consumer's scope.
        for paths, result in ((before, left), (after, right)):
            byte_limit = args.max_input_mib * 1024 * 1024
            check(sum(path.stat().st_size for path, _ in paths) <= byte_limit, 'inputs exceed configured byte limit')
            check([file_sha(path, byte_limit) for path, _ in paths] == [entry['source_sha256'] for entry in result['inputs']],
                  'input bytes changed before output')
        check(file_sha(exe) == exe_sha, 'CLI executable changed')
        empty = {'definitions': [], 'references': []}
        changes = []
        for key in sorted(set(left['groups']) | set(right['groups'])):
            l = side_summary(left['groups'].get(key, empty), args.before_complete)
            r = side_summary(right['groups'].get(key, empty), args.after_complete)
            # Report all symbols, including unchanged ones: occurrence provenance
            # may have changed even when counts are equal. No row-pairing is inferred.
            def attributes(side):
                # A multiset per role avoids guessing cross-version occurrence pairs.
                return collections.Counter((role, row['access_flags'], row['has_code'])
                    for role in ('definitions', 'references') for row in side[role])
            change = {'symbol': list(key), 'before': l, 'after': r,
                      'count_changed': (l['definition_count'], l['reference_count'], l['local_definition_count']) !=
                                       (r['definition_count'], r['reference_count'], r['local_definition_count']),
                      'attributes_changed': attributes(l) != attributes(r)}
            if args.code_digest and key[0] == 'method':
                change['code_changed'] = collections.Counter(row['code_sha256'] for row in l['definitions']) != \
                                         collections.Counter(row['code_sha256'] for row in r['definitions'])
            if args.reference_candidates:
                before_buckets = annotate_reference_candidates(l)
                after_buckets = annotate_reference_candidates(r)
                change['reference_candidate_summary'] = {
                    'before': before_buckets, 'after': after_buckets,
                    'bucket_counts_changed': before_buckets != after_buckets,
                    'scope_claim_changed': l['scope_complete'] != r['scope_complete'],
                    'semantics': 'observed_exact_symbols_no_cross_version_reference_pairing',
                }
            changes.append(change)
        result = {'schema_version': 1, 'scope': 'static supplied inputs only; no runtime resolution or row pairing',
                  'cli_sha256': exe_sha,
                  'before': {k: v for k, v in left.items() if k != 'groups'},
                  'after': {k: v for k, v in right.items() if k != 'groups'}, 'symbols': changes}
        if args.code_digest:
            result['code_fingerprint'] = {'format': 'raw-code-item-v1', 'debug_info_offset_normalized': True,
                                          'max_handler_items_per_side': args.code_max_handler_items}
        if args.reference_candidates:
            result['reference_candidate_model'] = {
                'version': 1, 'matching': 'exact_symbol_only', 'runtime_resolution': 'not_evaluated',
                'scope_authentication': 'caller_declared_only',
                'source_occurrences': occurrence_changes(left['sources'], right['sources']),
            }
        encoded = (json.dumps(result, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')
        check(len(encoded) <= 32 * 1024 * 1024, 'diff output exceeds 32 MiB')
        if target is not None:
            publish_output(target, encoded, protected)
        else:
            sys.stdout.buffer.write(encoded); sys.stdout.buffer.flush()
        return 0
    except (DiffError, OSError, ValueError, KeyError, TypeError) as error:
        print('dexdiff: ' + str(error), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())











