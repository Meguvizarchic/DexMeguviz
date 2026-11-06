"""Bounded raw/APK SourceSet admission around the existing independent metadata oracle."""
from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path
import re


class Unsupported(ValueError):
    status = 'Unsupported'


class Budget(ValueError):
    status = 'BudgetExceeded'


def need(value, message):
    if not value:
        raise ValueError(message)


class Work:
    def __init__(self):
        self.used = 0

    def charge(self, amount=1):
        if amount < 0 or amount > 4_000_000 - self.used:
            raise Budget('raw SourceSet structural/matching work limit')
        self.used += amount


def preflight(data, work):
    """Bound allocations/repeated ranges before the old parser materializes metadata.

    This is a resource preflight, not a second DEX-validity or instruction verifier.
    The independent parser still verifies headers/checksums/metadata semantics.
    """
    def word(at, width=4):
        work.charge()
        need(type(at) is int and 0 <= at <= len(data) - width, 'DEX preflight range')
        return int.from_bytes(data[at:at + width], 'little')

    def leb(at):
        value = 0
        for i in range(5):
            byte = word(at, 1); at += 1
            need(i < 4 or byte <= 15, 'DEX preflight ULEB overflow')
            value |= (byte & 127) << (7 * i)
            if byte < 128:
                return value, at
        raise ValueError('DEX preflight ULEB length')

    need(len(data) >= 112 and data[:4] == b'dex\n' and data[7] == 0, 'raw DEX header required')
    if data[4:7] not in (b'035', b'037', b'038', b'039', b'040'):
        raise Unsupported('only standard raw DEX 035/037/038/039/040')
    if word(40) == 0x78563412:
        raise Unsupported('reverse-endian DEX')
    need(word(40) == 0x12345678, 'DEX endian tag')
    tables = []
    for header, width in ((56, 4), (64, 4), (72, 12), (80, 8), (88, 8), (96, 32)):
        count, offset = word(header), word(header + 4)
        if count > 100_000:
            raise Budget('raw SourceSet table entry limit')
        work.charge(count)
        need(offset <= len(data) and count * width <= len(data) - offset, 'DEX table range')
        tables.append((count, offset))
    # String lengths are charged per string_id, including repeated offsets. The
    # base parser rejects malformed strings and allocates no more than this count.
    sizes = []
    count, offset = tables[0]
    for i in range(count):
        size, _ = leb(word(offset + i * 4))
        if size > 4096:
            raise Budget('raw SourceSet individual UTF16 length limit')
        work.charge(size)
        sizes.append(size)
    count, offset = tables[1]
    type_sizes = []
    for i in range(count):
        index = word(offset + i * 4)
        need(index < len(sizes), 'DEX type string reference')
        type_sizes.append(sizes[index])
    count, offset = tables[2]
    for i in range(count):
        at = offset + i * 12
        returned, params = word(at + 4), word(at + 8)
        need(returned < len(type_sizes), 'DEX return type reference')
        length = 2 + type_sizes[returned]
        if params:
            amount = word(params)
            if amount > 1024:
                raise Budget('raw SourceSet prototype parameter limit')
            work.charge(amount)
            need(params + 4 <= len(data) and amount * 2 <= len(data) - params - 4, 'DEX parameter list range')
            for n in range(amount):
                index = word(params + 4 + n * 2, 2)
                need(index < len(type_sizes), 'DEX parameter type reference')
                length += type_sizes[index]
        work.charge(length)
        if length > 16384:
            raise Budget('raw SourceSet materialized prototype limit')
    count, offset = tables[5]
    for i in range(count):
        cursor = word(offset + 32 * i + 24)
        if not cursor:
            continue
        lengths = []
        for _ in range(4):
            amount, cursor = leb(cursor)
            if amount > 100_000:
                raise Budget('raw SourceSet class_data entry limit')
            work.charge(amount)
            lengths.append(amount)
        for amount in lengths[:2]:
            for _ in range(amount):
                _, cursor = leb(cursor); _, cursor = leb(cursor)
        for amount in lengths[2:]:
            for _ in range(amount):
                _, cursor = leb(cursor); _, cursor = leb(cursor); code, cursor = leb(cursor)
                if code:
                    units = word(code + 12)
                    work.charge(units)
                    need(code + 16 <= len(data) and units * 2 <= len(data) - code - 16, 'DEX code range')


def module(name):
    path = Path(__file__).with_name(name + '.py')
    spec = importlib.util.spec_from_file_location('bounded_raw_' + name, path)
    need(spec is not None and spec.loader is not None, 'fixed oracle module unavailable')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def text(value, name, limit):
    need(type(value) is str and '\0' not in value and value, name + ' must be nonempty text')
    try:
        encoded = value.encode('utf-8')
    except UnicodeError as error:
        raise ValueError(name + ' must be UTF-8') from error
    need(len(encoded) <= limit, name + ' length limit')
    return value


def strict_type(actual, expected, name):
    need(type(actual) is type(expected), 'incorrect result type: ' + name)
    if isinstance(expected, dict):
        need(actual.keys() == expected.keys(), 'incorrect result keys: ' + name)
        for key in expected:
            strict_type(actual[key], expected[key], name + '.' + key)


def verify(manifest, manifest_path, query, result, read):
    need(type(manifest) is dict and set(manifest) == {'schema_version', 'namespace', 'scope_complete', 'inputs'}, 'raw source manifest shape')
    need(type(manifest['schema_version']) is int and manifest['schema_version'] == 1, 'raw source manifest version')
    need(type(manifest['scope_complete']) is bool, 'independent scope_complete boolean required')
    namespace = text(manifest['namespace'], 'namespace', 1024)
    supplied = manifest['inputs']
    if not isinstance(supplied, list) or not 1 <= len(supplied) <= 8:
        raise Budget('raw SourceSet needs 1..8 ordered inputs')
    if result.get('profile') != 'dex-query-method-v1' or result.get('execution_status') != 'Complete':
        raise Unsupported('raw SourceSet entry accepts completed dex-query-method-v1 attempts only')
    oracle, base = module('multisource'), module('verify')
    work = Work()
    # Exact/contains costs are bounded before the old matching loops execute.
    for key in ('name', 'owner'):
        if key in query.get('where', {}):
            spec = query['where'][key]
            pattern = tuple(spec['u16']) if 'u16' in spec else base.utf16_units(spec['value'])
            if len(pattern) > 256:
                raise Budget('raw SourceSet query matcher length limit')
    sources, inputs, slots = [], [], set()
    total_bytes = 0
    dex_bytes = 0
    apk = module('apk_entries')
    for index, item in enumerate(supplied):
        need(type(item) is dict and set(item) <= {'path', 'format', 'slot_key', 'role', 'expected_sha256', 'allow_no_dex'} and
             {'path', 'format', 'slot_key', 'role'} <= set(item), 'source input shape')
        fmt = item['format']
        if fmt not in ('RawDex', 'Apk'):
            raise Unsupported('only explicit raw DEX and bounded APK inputs')
        slot, role = text(item['slot_key'], 'slot_key', 1024), text(item['role'], 'role', 1024)
        allowed = item.get('allow_no_dex', False)
        need(type(allowed) is bool, 'allow_no_dex must be boolean')
        if index == 0:
            if role != 'base' or allowed:raise Unsupported('base must be first and require DEX')
        elif role not in ('code-split', 'resource-split') or allowed != (role == 'resource-split'):
            raise Unsupported('later roles must explicitly match code/resource split')
        if fmt == 'RawDex' and allowed:raise Unsupported('resource-only input must be an APK')
        need(slot not in slots, 'duplicate independent input slot'); slots.add(slot)
        path = Path(text(item['path'], 'input path', 4096))
        if not path.is_absolute():
            path = Path(manifest_path).resolve().parent / path
        data = read(path, min(16 * 1024 * 1024, 64 * 1024 * 1024 - total_bytes))
        total_bytes += len(data)
        digest = hashlib.sha256(data).hexdigest()
        wanted = item.get('expected_sha256')
        if 'expected_sha256' in item:
            need(type(wanted) is str and re.fullmatch('[0-9a-f]{64}', wanted), 'expected SHA256 format')
            need(wanted == digest, 'expected input digest mismatch')
        if fmt == 'Apk':
            expanded = apk.entries(data, allowed, 64 * 1024 * 1024 - dex_bytes, 16 - len(sources))
        else:
            if len(sources) >= 16 or len(data) > 64 * 1024 * 1024 - dex_bytes:
                raise Budget('logical source or aggregate DEX byte limit')
            expanded = [(None, None, data)]
        input_count = len(expanded)
        for entry_name, central_index, dex in expanded:
            dex_bytes += len(dex)
            work.charge((len(dex) + 4095) // 4096)
            preflight(dex, work)
            parsed = base.parse_dex(dex)
            for definition in parsed['definitions']:
                work.charge(1)
                for key in ('name', 'owner'):
                    if key in query.get('where', {}):
                        spec = query['where'][key]
                        wanted_units = tuple(spec['u16']) if 'u16' in spec else base.utf16_units(spec['value'])
                        actual_units = base.utf16_units(definition[key])
                        factor = max(1, len(wanted_units)) if spec.get('op', 'exact') == 'contains' else 1
                        work.charge(2 * max(1, len(actual_units)) * factor)
            dex_digest = parsed['source_sha256']
            content = f'sha256:raw-dex:v1:{len(dex)}:{dex_digest}'
            logical = 'logical-dex:v1:' + oracle.frame(content).decode('ascii') + 'header-offset:0'
            occurrence = oracle.occurrence_id(namespace, slot, role, entry_name, content)
            counts = {'strings': int.from_bytes(dex[56:60], 'little'), 'types': int.from_bytes(dex[64:68], 'little'),
                      'classes': int.from_bytes(dex[96:100], 'little'), 'method_refs': len(parsed['references']),
                      'method_defs': len(parsed['definitions'])}
            sources.append({'source_index': len(sources), 'input_index': index, 'input_slot_key': slot, 'slot_key': slot,
                            'role': role, 'entry_name': entry_name, 'central_index': central_index, 'source_sha256': dex_digest,
                            'content_id': content, 'occurrence_id': occurrence, 'logical_dex_id': logical,
                            'archive_sha256': digest if fmt == 'Apk' else '', 'version': parsed['version'],
                            'source_bytes': len(dex), 'counts': counts, 'bytes': dex, 'parsed': parsed})
        input_content = f"sha256:{'apk' if fmt == 'Apk' else 'raw-dex'}:v1:{len(data)}:{digest}"
        inputs.append({'input_index': index, 'path': str(path), 'slot_key': slot, 'role': role, 'format': fmt,
                       'source_sha256': digest, 'content_id': input_content, 'input_bytes': len(data), 'source_count': input_count,
                       'allow_no_dex': allowed, 'expected_digest_verified': wanted is not None})
    dataset = {'inputs': inputs, 'sources': sources, 'scope_complete': manifest['scope_complete'],
               'source_namespace': namespace, 'base_oracle': base,
               'snapshot_id': oracle.snapshot_id(namespace, manifest['scope_complete'], inputs, sources)}
    # The established oracle compares equality; enforce JSON types first so bool
    # cannot impersonate a uint field, including nested origin/count metadata.
    for key, expected in {'input_count': len(inputs), 'source_count': len(sources), 'scope_complete': True,
                          'input_bytes': total_bytes, 'dex_bytes': dex_bytes, 'snapshot_id': ''}.items():
        strict_type(result.get(key), expected, key)
    for key, expected in [('inputs', inputs), ('sources', sources)]:
        actual = result.get(key)
        need(type(actual) is list and len(actual) == len(expected), 'result source list size')
        fields = ('input_index', 'slot_key', 'role', 'format', 'source_sha256', 'content_id', 'input_bytes',
                  'source_count', 'allow_no_dex', 'expected_digest_verified') if key == 'inputs' else (
                  'source_index', 'input_index', 'slot_key', 'role', 'source_sha256', 'source_bytes',
                  'archive_sha256', 'content_id', 'occurrence_id', 'logical_dex_id', 'counts')
        for position, (got, want) in enumerate(zip(actual, expected)):
            need(type(got) is dict, 'result source record object')
            for field in fields:
                strict_type(got.get(field), want[field], f'{key}.{position}.{field}')
            if key == 'sources':
                strict_type(got.get('dex_version'), 35, 'source dex_version')
                strict_type(got.get('archive_entry_name'), '', 'source entry name')
                strict_type(got.get('archive_entry_index'), want['central_index'], 'source entry index')
                strict_type(got.get('expected_digest_verified'), False, 'source expected digest flag')
                need(got['expected_digest_verified'] is inputs[want['input_index']]['expected_digest_verified'], 'source expected digest flag mismatch')
    for row in result['candidates']:
        for key in ('source_index', 'input_index'):
            need(type(row.get(key)) is int and 0 <= row[key] < len(sources), 'candidate source index')
        for key in ('source_sha256', 'content_id', 'occurrence_id', 'logical_dex_id', 'snapshot_id'):
            strict_type(row.get(key), '', 'candidate ' + key)
    if 'counts' in result:
        strict_type(result['counts'], {'strings': 0, 'types': 0, 'classes': 0, 'method_refs': 0, 'method_defs': 0}, 'aggregate counts')
    if len(inputs) == 1 and len(sources) == 1 and inputs[0]['format'] == 'RawDex':
        strict_type(result.get('dex_version'), 35, 'top-level dex_version')
    report = oracle.verify_source_set_result(dataset, result, query)
    report['verification_scope'] = 'Independent bounded raw DEX/APK metadata, ordered declared SourceSet identities and supported static query evidence; no opcode/ART/runtime verification'
    report['preflight_work_units'] = work.used
    report['preflight_work_limit'] = 4_000_000
    report['declared_scope_decision_verified'] = result['decision'] in ('ProvenTrue', 'ProvenFalse')
    report['query_identity_verified'] = False
    report['source_scope_claim'] = 'caller_declared_complete' if manifest['scope_complete'] else 'caller_declared_incomplete'
    report['source_scope_authenticated'] = False
    return report
