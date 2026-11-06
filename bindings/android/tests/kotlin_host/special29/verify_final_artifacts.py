"""Validate fixed Kotlin/JNI predicates against one final AAR, DLL and CLI.

Outputs are created only in a new caller-specified C-workspace directory.
This uses real AAR classes.jar and an exact copy of the supplied Windows DLL.
It does not claim Android loading, ART execution, or whole-program verification.
"""
from pathlib import Path
from urllib.parse import unquote, urlsplit
import argparse
import glob
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parent
WORKSPACE = Path(r'<LOCAL_PATH>').resolve()
COMPILER_MANIFEST = Path(r'<LOCAL_PATH>')
DEFAULT_STDLIB = Path(r'<LOCAL_PATH>')
JDK = Path(r'C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot\bin')
STDLIB_HASH = 'bd8250210584cb659847dce9cda660f8e9906e5def7fbebcea93dc6dcb6a88a3'
FIXTURE_HASH = 'f3cf5a3b20041d69508b6841ab46b9e8f7168862bf7d34d2afbb70127eda49a7'
PACKAGE = 'io.github.jichuo1.dexmeguviz.'
KIND_TEST = ROOT/'tests/kotlin_host/Predicate29KindsTests.kt'
BRIDGE_TEST = ROOT/'tests/kotlin_host/Predicate29KindsBridgeTest.java'
CLI_ORACLE = ROOT/'tests/kotlin_host/verify_predicate29_kinds.py'
DEX_ORACLE = ROOT/'tests/kotlin_host/verify_special_methods_fixture.py'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def jar_from_aar(path):
    with zipfile.ZipFile(path) as archive:
        matches = [x for x in archive.infolist() if x.filename == 'classes.jar']
        if len(matches) != 1 or matches[0].is_dir() or matches[0].file_size > 16*1024*1024:
            raise ValueError('AAR must contain one bounded classes.jar')
        data = archive.read(matches[0])
    with zipfile.ZipFile(io.BytesIO(data)) as jar:
        names = jar.namelist()
        if len(names) != len(set(names)) or any(n.startswith('kotlin/') for n in names):
            raise ValueError('duplicate classes.jar entry or bundled Kotlin runtime')
        prefix = 'io/github/jichuo1/dexmeguviz/'
        for name in ('MethodPredicate.class', 'MethodPredicate$Companion.class', 'MethodQuery.class',
                     'QueryExecution.class', 'NativeEngine.class', 'NativeEngine$Snapshot.class'):
            if prefix + name not in names:
                raise ValueError('missing final AAR class: ' + name)
    return data


def class_source(log, name, jar):
    expression = re.compile(r'\]\s+' + re.escape(PACKAGE + name) + r'\s+source:\s+(\S+)')
    sources = [m.group(1) for line in log.splitlines() if (m := expression.search(line))]
    if len(sources) != 1:
        raise ValueError('class source missing or nonunique: ' + name)
    parsed = urlsplit(sources[0])
    if parsed.scheme != 'file' or parsed.netloc not in ('', 'localhost'):
        raise ValueError('class source is not local: ' + sources[0])
    value = unquote(parsed.path)
    if re.match(r'^/[A-Za-z]:/', value): value = value[1:]
    if os.path.normcase(os.path.abspath(value)) != os.path.normcase(os.path.abspath(jar)):
        raise ValueError('class did not load from final AAR classes.jar: ' + name)


def main():
    if os.name != 'nt': raise ValueError('Windows required for the supplied JNI DLL')
    p = argparse.ArgumentParser()
    for name in ('aar', 'jni', 'cli', 'out'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--fixture', type=Path, default=ROOT/'fixture/special-methods.dex')
    p.add_argument('--stdlib', type=Path, default=DEFAULT_STDLIB)
    for name in ('aar', 'jni', 'cli'):
        p.add_argument('--' + name + '-sha256')
    a = p.parse_args()
    aar, jni, cli, fixture, stdlib = [x.resolve(strict=True) for x in (a.aar, a.jni, a.cli, a.fixture, a.stdlib)]
    out = a.out.resolve()
    if not out.is_relative_to(WORKSPACE) or out == WORKSPACE or out.is_relative_to(ROOT) or out.exists():
        raise ValueError('output must be a new directory in the writable C workspace, outside test sources')
    for path in (aar, jni, cli, fixture, stdlib, KIND_TEST, BRIDGE_TEST, CLI_ORACLE, DEX_ORACLE, COMPILER_MANIFEST):
        if not path.is_file() or path.is_symlink(): raise ValueError('missing or non-regular input: ' + str(path))
        if path.is_relative_to(out): raise ValueError('output contains an input')
    compiler = json.loads(COMPILER_MANIFEST.read_text(encoding='utf-8'))
    compiler_paths = [Path(item['path']).resolve(strict=True) for item in compiler]
    for item, path in zip(compiler, compiler_paths):
        if digest(path) != item['sha256']: raise ValueError('compiler input changed: ' + str(path))
    annotations = next(path for path in compiler_paths if path.name == 'annotations-13.0.jar')
    if digest(fixture) != FIXTURE_HASH or digest(stdlib) != STDLIB_HASH:
        raise ValueError('fixture or host-provided Kotlin 2.4.21 stdlib hash mismatch')
    for label, path, expected in [('aar', aar, a.aar_sha256), ('jni', jni, a.jni_sha256), ('cli', cli, a.cli_sha256)]:
        if expected is not None and (not re.fullmatch(r'[0-9a-f]{64}', expected) or digest(path) != expected):
            raise ValueError(label + ' does not match expected SHA-256')
    inputs = {'aar': aar, 'jni': jni, 'cli': cli, 'fixture': fixture, 'stdlib': stdlib,
              'compiler_manifest': COMPILER_MANIFEST, 'kotlin_test': KIND_TEST, 'jni_test': BRIDGE_TEST,
              'cli_oracle': CLI_ORACLE, 'dex_oracle': DEX_ORACLE, 'runner': Path(__file__).resolve(),
              'java': JDK/'java.exe', 'javac': JDK/'javac.exe'}
    for i, path in enumerate(compiler_paths): inputs['compiler_' + str(i)] = path
    before = {name: digest(path) for name, path in inputs.items()}
    jar_data = jar_from_aar(aar)
    out.mkdir(parents=True, exist_ok=False)
    jar = out/'classes.jar'; jar.write_bytes(jar_data)
    native = out/'native'; native.mkdir(); dll = native/'dexmeguviz.dll'; shutil.copyfile(jni, dll)
    if digest(dll) != before['jni']: raise ValueError('copied JNI DLL does not match input')
    testclasses = out/'test-classes'; testclasses.mkdir()
    empty_source = out/'empty-source'; empty_source.mkdir()
    temporary = out/'tmp'; temporary.mkdir()
    userdir = out/'user'; userdir.mkdir()
    runner = out/'FinalDllRunner.java'
    runner.write_text('''package io.github.jichuo1.dexmeguviz;
public final class FinalDllRunner {
    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        Predicate29KindsBridgeTest.main(new String[]{args[1]});
    }
}
''', encoding='utf-8')
    (out/'inputs-before.json').write_text(json.dumps({'sha256': before, 'paths': {k:str(v) for k,v in inputs.items()},
        'classes_jar_sha256': hashlib.sha256(jar_data).hexdigest()}, indent=2) + '\n', encoding='utf-8')
    env = os.environ.copy()
    for key in ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH'): env.pop(key, None)
    env['PYTHONDONTWRITEBYTECODE'] = '1'; env['TEMP'] = str(temporary); env['TMP'] = str(temporary)
    env['PATH'] = os.pathsep.join(sorted(glob.glob(r'C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64'), reverse=True)+[env.get('PATH','')])
    compiler_cp = os.pathsep.join(map(str, compiler_paths))
    runtime_cp = os.pathsep.join(map(str, (testclasses, jar, stdlib)))
    records = []

    def run(name, command, timeout=180):
        start = time.monotonic()
        try:
            result = subprocess.run([str(x) for x in command], cwd=out, env=env, capture_output=True, timeout=timeout)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, code = exc.stdout or b'', exc.stderr or b'', -1
        (out/(name+'.stdout.log')).write_bytes(stdout); (out/(name+'.stderr.log')).write_bytes(stderr)
        records.append({'name':name, 'argv':[str(x) for x in command], 'exit_code':code, 'seconds':round(time.monotonic()-start,3)})
        (out/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
        print(name, code, flush=True)
        if code: raise RuntimeError(name + ' failed; logs retained')
        return stdout.decode('utf-8','replace'), stderr.decode('utf-8','replace')

    outcome = 'failed before completion'
    try:
        run('fixture-oracle',[sys.executable,'-B',DEX_ORACLE,'--fixture',fixture])
        run('kotlinc',[JDK/'java.exe','-XX:+PerfDisableSharedMem','-Djava.io.tmpdir='+str(temporary),'-Duser.home='+str(userdir),
            '-cp',compiler_cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','17',
            '-classpath',os.pathsep.join(map(str,(stdlib,annotations,jar))),KIND_TEST,'-d',testclasses])
        run('kotlin',[JDK/'java.exe','-Xmx128m','-XX:+PerfDisableSharedMem','-Djava.io.tmpdir='+str(temporary),
            '-Duser.home='+str(userdir),'-cp',runtime_cp,PACKAGE+'Predicate29KindsTestsKt'])
        run('cli-comparison',[sys.executable,'-B',CLI_ORACLE,'--exe',cli,'--fixture',fixture,'--lines',out/'kotlin.stdout.log'])
        run('javac',[JDK/'javac.exe','-J-XX:+PerfDisableSharedMem','-J-Djava.io.tmpdir='+str(temporary),'-J-Duser.home='+str(userdir),
            '--release','17','-sourcepath',empty_source,'-cp',os.pathsep.join(map(str,(jar,stdlib))),'-d',testclasses,BRIDGE_TEST,runner])
        stdout, stderr = run('jni',[JDK/'java.exe','-ea','-Xcheck:jni','-XX:+PerfDisableSharedMem',
            '-Djava.io.tmpdir='+str(temporary),'-Duser.home='+str(userdir),'-Xlog:class+load=info',
            '-Djava.library.path='+str(native),'-cp',runtime_cp,PACKAGE+'FinalDllRunner',dll.resolve(),fixture],timeout=300)
        combined = stdout+'\n'+stderr
        if 'PASS 10 method-kind and owner-flags cases through Windows JNI' not in stdout or re.search(
                r'WARNING in native method|FATAL ERROR in native method|JNI DETECTED ERROR',combined):
            raise ValueError('JNI bridge did not pass cleanly under -Xcheck:jni')
        for name in ('MethodPredicate','MethodPredicate$Companion','MethodQuery','QueryExecution','NativeEngine','NativeEngine$Snapshot'):
            class_source(combined,name,jar)
        if digest(dll) != before['jni'] or digest(jar) != hashlib.sha256(jar_data).hexdigest():
            raise ValueError('copied DLL or extracted AAR classes changed')
        outcome = 'passed'
    finally:
        after = {}
        for name, path in inputs.items():
            try: after[name] = digest(path)
            except OSError: after[name] = None
        changed = [name for name in before if before[name] != after[name]]
        if changed and outcome == 'passed': outcome = 'failed: inputs changed'
        (out/'summary.json').write_text(json.dumps({'outcome':outcome,'input_sha256_before':before,'input_sha256_after':after,
            'changed_inputs':changed,'classes_jar_sha256':hashlib.sha256(jar_data).hexdigest(),'commands':records,
            'scope':'Windows JVM, actual AAR classes.jar, supplied JNI DLL bytes and fixed DEX CLI; no Android or ART proof'},indent=2)+'\n',encoding='utf-8')
        if changed: raise RuntimeError('input changed during validation; see summary.json')
    print('PASS final AAR classes, 10 CLI cases and 10 Windows JNI cases')


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, RuntimeError, KeyError, StopIteration, zipfile.BadZipFile) as error:
        print('Final artifact validation failed:', error, file=sys.stderr)
        raise SystemExit(1)
