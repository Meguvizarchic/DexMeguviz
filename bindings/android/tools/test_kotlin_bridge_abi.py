"""Reject same-name Kotlin bridge classes with their required method ABI altered."""
import argparse
import copy
import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

from jni_classfile import parse


def mutate_aar(original, class_name, method_name, descriptor, field):
    prefix = 'io/github/jichuo1/dexmeguviz/'
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(original)) as src, zipfile.ZipFile(output, 'w') as dest:
        for entry in src.infolist():
            data = src.read(entry)
            if entry.filename == 'classes.jar':
                nested = io.BytesIO()
                with zipfile.ZipFile(io.BytesIO(data)) as old, zipfile.ZipFile(nested, 'w') as new:
                    for item in old.infolist():
                        content = old.read(item)
                        if item.filename == prefix + class_name + '.class':
                            raw = bytearray(content)
                            matches = [m for m in parse(raw)['methods'] if m['name'] == method_name and m['descriptor'] == descriptor]
                            if len(matches) != 1:
                                raise ValueError('required method not found uniquely')
                            method = matches[0]
                            offset = method[field + '_offset']
                            original_value = method[field]
                            replacement = original_value[:-2] + b'X' + original_value[-1:] if field == 'descriptor' else original_value[:-1] + b'X'
                            if len(replacement) != len(original_value) or replacement == original_value:
                                raise ValueError('invalid mutation')
                            raw[offset:offset + len(original_value)] = replacement
                            content = bytes(raw)
                        new.writestr(item, content)
                data = nested.getvalue()
            dest.writestr(entry, data)
    return output.getvalue()


def run():
    parser = argparse.ArgumentParser()
    for name in ('aar', 'pom', 'module', 'header', 'readelf', 'runtime-report', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    original = args.aar.read_bytes()
    original_module = json.loads(args.module.read_text(encoding='utf-8'))
    prefix = b'Lio/github/jichuo1/dexmeguviz/'
    tests = [
        ('text-value-name', 'MethodPredicate$Companion', b'textValue',
         b'(' + prefix + b'MethodTextField;' + prefix + b'TextOperation;Ljava/lang/String;Z)' + prefix + b'MethodPredicate;', 'name'),
        ('snapshot-execute-descriptor', 'QueryExecution', b'execute',
         b'(' + prefix + b'NativeEngine$Snapshot;' + prefix + b'MethodQuery;)' + prefix + b'NativeEngine$QueryResult;', 'descriptor'),
        ('source-set-execute-descriptor', 'QueryExecution', b'execute',
         b'(' + prefix + b'NativeEngine$SourceSetSnapshot;' + prefix + b'MethodQuery;)' + prefix + b'NativeEngine$QueryResult;', 'descriptor'),
        ('snapshot-entity-execute-descriptor', 'QueryExecution', b'execute',
         b'(' + prefix + b'NativeEngine$Snapshot;' + prefix + b'EntityQuery;)' + prefix + b'NativeEngine$EntityResult;', 'descriptor'),
        ('source-set-entity-execute-descriptor', 'QueryExecution', b'execute',
         b'(' + prefix + b'NativeEngine$SourceSetSnapshot;' + prefix + b'EntityQuery;)' + prefix + b'NativeEngine$EntityResult;', 'descriptor'),
        ('snapshot-entity-job-descriptor', 'QueryExecution', b'startEntityJob',
         b'(' + prefix + b'NativeEngine$Snapshot;' + prefix + b'EntityQuery;IIJ)' + prefix + b'NativeEngine$EntityJob;', 'descriptor'),
        ('source-set-entity-job-descriptor', 'QueryExecution', b'startEntityJob',
         b'(' + prefix + b'NativeEngine$SourceSetSnapshot;' + prefix + b'EntityQuery;IIJ)' + prefix + b'NativeEngine$EntityJob;', 'descriptor'),
        ('snapshot-method-job-descriptor', 'QueryExecution', b'startMethodJob',
         b'(' + prefix + b'NativeEngine$Snapshot;' + prefix + b'MethodQuery;IIJ)' + prefix + b'NativeEngine$Job;', 'descriptor'),
        ('source-set-method-job-descriptor', 'QueryExecution', b'startMethodJob',
         b'(' + prefix + b'NativeEngine$SourceSetSnapshot;' + prefix + b'MethodQuery;IIJ)' + prefix + b'NativeEngine$Job;', 'descriptor'),
        ('snapshot-graph-execute-descriptor', 'GraphQueryExecution', b'execute',
         b'(' + prefix + b'NativeEngine$Snapshot;[B)' + prefix + b'GraphResult;', 'descriptor'),
        ('source-set-graph-execute-descriptor', 'GraphQueryExecution', b'execute',
         b'(' + prefix + b'NativeEngine$SourceSetSnapshot;[B)' + prefix + b'GraphResult;', 'descriptor'),
        ('snapshot-graph-job-descriptor', 'GraphQueryExecution', b'startGraphJob',
         b'(' + prefix + b'NativeEngine$Snapshot;[BIIJ)' + prefix + b'NativeEngine$GraphJob;', 'descriptor'),
        ('source-set-graph-job-descriptor', 'GraphQueryExecution', b'startGraphJob',
         b'(' + prefix + b'NativeEngine$SourceSetSnapshot;[BIIJ)' + prefix + b'NativeEngine$GraphJob;', 'descriptor'),
        ('owner-flags-name', 'MethodPredicate$Companion', b'ownerFlags',
         b'(' + prefix + b'RawFlagOperation;' + prefix + b'RawDexFlags;)' + prefix + b'MethodPredicate;', 'name'),
        ('parameter-count-exact-descriptor', 'MethodPredicate$Companion', b'parameterCount',
         b'(J)' + prefix + b'MethodPredicate;', 'descriptor'),
        ('parameter-count-range-descriptor', 'MethodPredicate$Companion', b'parameterCount',
         b'(JJ)' + prefix + b'MethodPredicate;', 'descriptor'),
        ('parameter-name', 'MethodPredicate$Companion', b'parameter',
         b'(J' + prefix + b'TextOperation;Ljava/lang/String;Z)' + prefix + b'MethodPredicate;', 'name'),
        ('uses-string-name', 'MethodPredicate$Companion', b'usesString',
         b'(' + prefix + b'TextOperation;Ljava/lang/String;Z)' + prefix + b'MethodPredicate;', 'name'),
        ('constructor-name', 'MethodPredicate$Companion', b'constructor',
         b'()' + prefix + b'MethodPredicate;', 'name'),
        ('class-initializer-name', 'MethodPredicate$Companion', b'classInitializer',
         b'()' + prefix + b'MethodPredicate;', 'name'),
        ('normal-method-name', 'MethodPredicate$Companion', b'normalMethod',
         b'()' + prefix + b'MethodPredicate;', 'name'),
        ('entity-text-value-name', 'EntityPredicate$Companion', b'textValue',
         b'(' + prefix + b'EntityTextField;' + prefix + b'TextOperation;Ljava/lang/String;Z)' + prefix + b'EntityPredicate;', 'name'),
        ('entity-flags-name', 'EntityPredicate$Companion', b'flags',
         b'(' + prefix + b'RawFlagOperation;' + prefix + b'RawDexFlags;)' + prefix + b'EntityPredicate;', 'name'),
        ('entity-local-definition-name', 'EntityPredicate$Companion', b'hasLocalDefinition',
         b'(Z)' + prefix + b'EntityPredicate;', 'name'),
        ('entity-query-constructor-descriptor', 'EntityQuery', b'<init>',
         b'(' + prefix + b'EntityRelation;' + prefix + b'EntityPredicate;' + prefix + b'QueryIntent;IJ)V', 'descriptor'),
    ]
    verifier = Path(__file__).with_name('verify_aar.py')
    records = []
    for label, class_name, name, descriptor, field in tests:
        payload = mutate_aar(original, class_name, name, descriptor, field)
        aar = args.out / (label + '.aar'); aar.write_bytes(payload)
        metadata = copy.deepcopy(original_module)
        for variant in metadata['variants']:
            for item in variant['files']:
                item['size'] = len(payload)
                for algorithm in ('sha256', 'sha512', 'sha1', 'md5'):
                    if algorithm in item:
                        item[algorithm] = hashlib.new(algorithm, payload).hexdigest()
        module = args.out / (label + '.module')
        module.write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
        command = [sys.executable, '-B', str(verifier), '--aar', str(aar), '--pom', str(args.pom),
                   '--module', str(module), '--header', str(args.header), '--readelf', str(args.readelf),
                   '--runtime-report', str(args.runtime_report), '--expect-kotlin', '--out', str(args.out / (label + '-audit'))]
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90)
        (args.out / (label + '.stdout.log')).write_text(result.stdout, encoding='utf-8')
        (args.out / (label + '.stderr.log')).write_text(result.stderr, encoding='utf-8')
        records.append({'case': label, 'sha256': hashlib.sha256(payload).hexdigest(), 'exit_code': result.returncode, 'stderr': result.stderr.strip()})
        if result.returncode == 0 or 'Kotlin bridge method mismatch' not in result.stderr:
            raise SystemExit('unexpected verifier result: ' + label)
    (args.out / 'records.json').write_text(json.dumps(records, indent=2) + '\n', encoding='utf-8')
    print('PASS Kotlin bridge and method-predicate ABI mutations rejected')


if __name__ == '__main__':
    run()

