"""Inspect a built AAR and its ELF exports without running Android binaries."""
from pathlib import Path
from zipfile import ZipFile, BadZipFile, ZIP_STORED, ZIP_DEFLATED
import argparse,hashlib,io,json,re,subprocess,zlib,xml.etree.ElementTree as ET
from encoded_value_audit import ENCODED_VALUE_CLASSES,check_encoded_value_class
from jni_classfile import ADVANCED_CLASSES,METHOD_CALLS_CLASSES,METHOD_FACTS_CLASSES,METHOD_PARAMETERS_CLASSES,SCOPED_METHOD_CLASSES,ANNOTATION_CLASSES,SOURCE_EXPORT_CLASSES,OPCODE_CLASSES,SCOPED_OPCODE_CLASSES,CLASS_ANNOTATION_QUERY_CLASSES,SCOPED_CLASS_ANNOTATION_CLASSES,CLASS_ANNOTATION_STRING_CLASSES,METHOD_BATCH_CLASSES,SCOPED_METHOD_BATCH_CLASSES,ClassError,parse,verify_classfiles,verify_keep

# Conservative limits for this fixed packaging profile. They apply before any
# archive member is decompressed, independently of the ZIP's compression ratio.
MIB=1024*1024
AAR_BYTES=64*MIB
AAR_ENTRIES=4096
AAR_TOTAL_UNCOMPRESSED=256*MIB
AAR_MEMBER=64*MIB
JAR_BYTES=32*MIB
JAR_ENTRIES=4096
JAR_TOTAL_UNCOMPRESSED=64*MIB
JAR_MEMBER=8*MIB
TEXT_MEMBER=1*MIB
HEADER_BYTES=2*MIB
REPORT_BYTES=16*MIB
POM_BYTES=2*MIB
MODULE_BYTES=4*MIB

def file_bytes(path,limit):
    with path.open('rb') as f:data=f.read(limit+1)
    if len(data)>limit:raise ValueError('input file exceeds audit size limit: '+str(path))
    return data

def check_archive(archive,max_entries,max_total,max_member,label):
    entries=archive.infolist()
    if len(entries)>max_entries:raise ValueError(label+' has too many entries')
    names=[x.filename for x in entries]
    if len(names)!=len(set(names)):raise ValueError('duplicate '+label+' entry name')
    total=0
    for entry in entries:
        if entry.file_size>max_member:raise ValueError(label+' entry exceeds decompression limit: '+entry.filename)
        total+=entry.file_size
        if total>max_total:raise ValueError(label+' aggregate exceeds decompression limit')
        if entry.compress_type not in (ZIP_STORED,ZIP_DEFLATED):raise ValueError(label+' unsupported compression')
        if entry.flag_bits&1:raise ValueError(label+' encrypted entries are unsupported')

def member_bytes(archive,name,limit):
    info=archive.getinfo(name)
    if info.file_size>limit:raise ValueError('entry exceeds decompression limit: '+name)
    with archive.open(info) as source:data=source.read(limit+1)
    if len(data)!=info.file_size or len(data)>limit:raise ValueError('invalid entry length: '+name)
    return data


def check_annotation_matcher_class(clazz,name):
    prefix=b'io/github/jichuo1/dexmeguviz/'
    methods={(m['name'],m['descriptor'],m['access']) for m in clazz['methods'] if m['access']&1}
    fields={(f['name'],f['descriptor'],f['access']) for f in clazz['fields'] if f['access']&1}
    if name=='AnnotationMatcher':
        if clazz['flags']!=0x0031 or clazz['superclass']!=b'java/lang/Object':raise ValueError('invalid annotation matcher class')
        item=b'L'+prefix+b'AnnotationResult$Item;'
        limits=b'L'+prefix+b'EncodedValue$Limits;'
        resolver=b'L'+prefix+b'AnnotationMatcher$Resolver;'
        common=b'('+item+b'Ljava/lang/String;ILjava/lang/String;I'
        want={(b'metadata',b'('+item+b'Ljava/lang/String;I)I',9),
              (b'scalar',common+b'JI'+limits+b')I',9),
              (b'text',common+b'Ljava/lang/String;'+resolver+b'I'+limits+b')I',9)}
        if methods!=want or fields!={(n,b'I',25) for n in (b'NO_MATCH',b'MATCH',b'UNKNOWN')}:raise ValueError('invalid annotation matcher API')
    elif name=='AnnotationArrayMatcher':
        if clazz['flags']!=0x0031 or clazz['superclass']!=b'java/lang/Object' or fields:raise ValueError('invalid annotation array matcher class')
        item=b'L'+prefix+b'AnnotationResult$Item;'
        limits=b'L'+prefix+b'EncodedValue$Limits;'
        want={(name,b'('+item+b'Ljava/lang/String;ILjava/lang/String;[I[JI'+limits+b')I',9) for name in (b'exact',b'subsequence')}
        want.add((b'unorderedScalars',b'('+item+b'Ljava/lang/String;ILjava/lang/String;[I[JZI'+limits+b')I',9))
        if methods!=want:raise ValueError('invalid annotation array matcher API')
    elif name=='BoundAnnotationText':
        if clazz['flags']!=0x0031 or clazz['superclass']!=b'java/lang/Object' or fields:raise ValueError('invalid bound annotation matcher class')
        result=b'L'+prefix+b'AnnotationResult;'
        bound=b'L'+prefix+b'BoundAnnotationText;'
        limits=b'L'+prefix+b'EncodedValue$Limits;'
        want={(b'bind',b'('+result+b'L'+prefix+b'NativeEngine$Snapshot;I)'+bound,9),
              (b'bind',b'('+result+b'L'+prefix+b'NativeEngine$SourceSetSnapshot;I)'+bound,9),
              (b'text',b'(ILjava/lang/String;ILjava/lang/String;ILjava/lang/String;I'+limits+b')I',1)}
        if methods!=want:raise ValueError('invalid bound annotation matcher API')
    elif name=='AnnotationMatcher$Resolver':
        if clazz['flags']!=0x0601 or clazz['superclass']!=b'java/lang/Object' or fields or methods!={(b'resolve',b'(IJ)Ljava/lang/String;',0x0401)}:raise ValueError('invalid annotation resolver API')
    else:raise ValueError('unexpected annotation matcher class')


def check_runtime_report(text):
    if 'FAILED' in text:raise ValueError('runtime dependency report contains failure')
    lines=text.splitlines()
    header=re.compile(r'^\s*releaseRuntimeClasspath(?:\s+-\s+.*)?\s*$')
    matches=[i for i,line in enumerate(lines) if header.fullmatch(line)]
    if len(matches)!=1:raise ValueError('releaseRuntimeClasspath section missing or duplicated')
    section=[]
    config=re.compile(r'^[A-Za-z][A-Za-z0-9_.-]*\s+-\s+\S')
    footer=('A web-based, searchable dependency report','[Incubating]','Deprecated Gradle features',
            'BUILD SUCCESSFUL','BUILD FAILED','For more on this','Consider enabling','Picked up JAVA_TOOL_OPTIONS')
    for line in lines[matches[0]+1:]:
        value=line.strip()
        if not value:continue
        if config.match(value) or value.startswith(footer) or re.match(r'^\d+ actionable tasks?',value):break
        section.append(value)
    if section!=['No dependencies']:raise ValueError('releaseRuntimeClasspath is not an empty dependency section')


def check_elf_header(text,abi):
    expected={'arm64-v8a':('ELF64','AArch64'),'armeabi-v7a':('ELF32','ARM')}
    if abi not in expected:raise ValueError('unknown ABI: '+abi)
    elfclass,machine=expected[abi]
    fields={}
    for name in ('Class','Data','Type','Machine'):
        found=re.findall(r'^\s*'+name+r':\s*(.*?)\s*$',text,re.M)
        if len(found)!=1:raise ValueError('missing or duplicated ELF header '+name+': '+abi)
        fields[name]=found[0]
    if fields['Class']!=elfclass or fields['Data']!="2's complement, little endian" or \
       not re.fullmatch(r'DYN(?:\s+\(Shared object file\))?',fields['Type']) or fields['Machine']!=machine:
        raise ValueError('invalid ELF class, endianness, type or machine: '+abi)


def check_elf_symbols(text,expected,abi):
    exports=[];undefined=[]
    pattern=re.compile(r'^\s*\d+:\s+\S+\s+\d+\s+(\S+)\s+(GLOBAL|WEAK)\s+(DEFAULT|PROTECTED)\s+(\S+)\s+(\S+)',re.M)
    for match in pattern.finditer(text):
        kind,binding,visibility,section,raw=match.groups()
        if section=='UND':
            undefined.append(raw.split('@',1)[0]);continue
        name=raw.split('@',1)[0]
        if name not in expected:raise ValueError('unexpected export: '+abi+' '+raw)
        if raw!=name or kind!='FUNC' or binding!='GLOBAL' or visibility!='DEFAULT' or not section.isdecimal() or int(section)==0:
            raise ValueError('invalid export type, binding, visibility, section or version: '+abi+' '+raw)
        if name in exports:raise ValueError('duplicate export: '+abi+' '+name)
        exports.append(name)
    if set(exports)!=expected:raise ValueError('missing export: '+abi)
    return exports,undefined


def unique_json_pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate module metadata key: '+key)
        result[key]=value
    return result


def check_publication(pom_bytes,module_bytes,aar_bytes):
    if re.search(br'<!DOCTYPE',pom_bytes,re.I):raise ValueError('POM DOCTYPE unsupported')
    pom=ET.fromstring(pom_bytes)
    ns='{http://maven.apache.org/POM/4.0.0}'
    if pom.tag!=ns+'project':raise ValueError('invalid POM project root')
    if pom.findall('.//{*}dependency') or pom.findall('.//{*}parent'):
        raise ValueError('POM has dependency or inherited parent')
    def coordinate(name):
        items=pom.findall(ns+name)
        if len(items)!=1 or not items[0].text or not items[0].text.strip() or '${' in items[0].text:
            raise ValueError('invalid POM '+name)
        return items[0].text.strip()
    group,artifact,version,packaging=(coordinate(n) for n in ('groupId','artifactId','version','packaging'))
    if packaging!='aar':raise ValueError('POM packaging is not aar')
    expected_name=artifact+'-'+version+'.aar'
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.aar',expected_name) or '..' in expected_name:
        raise ValueError('invalid module artifact name/url')
    metadata=json.loads(module_bytes.decode('utf-8'),object_pairs_hook=unique_json_pairs)
    if not isinstance(metadata,dict) or metadata.get('formatVersion')!='1.1':raise ValueError('invalid module format')
    component=metadata.get('component')
    if not isinstance(component,dict) or (component.get('group'),component.get('module'),component.get('version'))!=(group,artifact,version):
        raise ValueError('POM/module coordinates differ')
    variants=metadata.get('variants')
    if not isinstance(variants,list) or len(variants)!=2:raise ValueError('expected two module variants')
    usages=[];names=[];artifact_name=None
    for variant in variants:
        if not isinstance(variant,dict) or not isinstance(variant.get('name'),str) or not variant['name']:
            raise ValueError('invalid module variant')
        names.append(variant['name'])
        for key in ('dependencies','dependencyConstraints'):
            if key in variant and (not isinstance(variant[key],list) or variant[key]):
                raise ValueError('module variant has dependencies or constraints')
        if 'available-at' in variant:raise ValueError('module variant redirects externally')
        attributes=variant.get('attributes')
        if not isinstance(attributes,dict):raise ValueError('module variant attributes missing')
        usage=attributes.get('org.gradle.usage')
        if usage not in ('java-api','java-runtime'):raise ValueError('invalid module usage')
        usages.append(usage)
        files=variant.get('files')
        if not isinstance(files,list) or len(files)!=1 or not isinstance(files[0],dict):raise ValueError('invalid module artifact list')
        record=files[0];name=record.get('name');url=record.get('url')
        if name!=expected_name or url!=expected_name:
            raise ValueError('invalid module artifact name/url')
        if artifact_name is not None and artifact_name!=name:raise ValueError('module variants reference different artifacts')
        artifact_name=name
        if type(record.get('size')) is not int or record['size']!=len(aar_bytes) or record.get('sha256')!=hashlib.sha256(aar_bytes).hexdigest():
            raise ValueError('module artifact does not match audited AAR')
        for algorithm in ('sha512','sha1','md5'):
            if algorithm in record and record[algorithm]!=hashlib.new(algorithm,aar_bytes).hexdigest():
                raise ValueError('module artifact '+algorithm+' mismatch')
    if len(set(names))!=2 or sorted(usages)!=['java-api','java-runtime']:
        raise ValueError('module variants must contain one API and one runtime variant')
    return {'group':group,'artifact':artifact,'version':version,'aar_sha256':hashlib.sha256(aar_bytes).hexdigest()}


def check_binder_class(clazz,name):
    prefix=b'io/github/jichuo1/dexmeguviz/RuntimeMethodBinder'
    enum=name in ('RuntimeMethodBinder$Status','RuntimeMethodBinder$Origin','RuntimeMethodBinder$InvocationKind')
    flags=0x4031 if enum else 0x0030 if name=='RuntimeMethodBinder$Signature' else 0x0031
    parent=b'java/lang/Enum' if enum else b'java/lang/Object'
    if clazz['flags']!=flags or clazz['superclass']!=parent:raise ValueError('unexpected binder class flags: '+name)
    public_methods={(m['name'],m['descriptor'],m['access']) for m in clazz['methods'] if m['access']&1}
    public_fields={(f['name'],f['descriptor'],f['access']) for f in clazz['fields'] if f['access']&1}
    result=b'L'+prefix+b'$Result;'; status=b'L'+prefix+b'$Status;'; origin=b'L'+prefix+b'$Origin;'
    if name=='RuntimeMethodBinder':
        expected={(b'bind',b'(Ljava/lang/ClassLoader;Ljava/lang/Object;Lio/github/jichuo1/dexmeguviz/NativeEngine$MethodCandidate;)'+result,9),
                  (b'bindDescriptor',b'(Ljava/lang/ClassLoader;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)'+result,9)}
        if public_methods!=expected or public_fields:raise ValueError('unexpected binder API')
    elif name=='RuntimeMethodBinder$Result':
        expected={(b'isForGeneration',b'(Ljava/lang/Object;)Z',1)}
        fields={b'status':status,b'origin':origin,b'declaredOwner':b'Ljava/lang/String;',b'name':b'Ljava/lang/String;',b'prototype':b'Ljava/lang/String;',
                b'initiatingLoader':b'Ljava/lang/ClassLoader;',b'definingLoader':b'Ljava/lang/ClassLoader;',b'definingLoaderKnown':b'Z',b'loaderGeneration':b'Ljava/lang/Object;',
                b'expectedInvocationKind':b'L'+prefix+b'$InvocationKind;',b'actualInvocationKind':b'L'+prefix+b'$InvocationKind;',b'declaringClass':b'Ljava/lang/Class;',b'method':b'Ljava/lang/reflect/Method;',b'sourceIndex':b'I',b'inputIndex':b'I',
                b'sourceSlot':b'Ljava/lang/String;',b'occurrenceId':b'Ljava/lang/String;'}
        if public_methods!=expected or public_fields!={(n,d,17) for n,d in fields.items()}:raise ValueError('unexpected binder result ABI')
    elif enum:
        typ=b'L'+prefix+(b'$Status;' if name.endswith('$Status') else b'$Origin;' if name.endswith('$Origin') else b'$InvocationKind;')
        values=(['BOUND','INVALID_INPUT','UNSUPPORTED_MEMBER','OWNER_NOT_FOUND','SIGNATURE_TYPE_NOT_FOUND','SIGNATURE_MISMATCH','INVOCATION_MISMATCH','AMBIGUOUS','LOADER_ERROR','REFLECTION_ERROR'] if name.endswith('$Status') else ['UNVERIFIED'] if name.endswith('$Origin') else ['STATIC','INSTANCE','UNKNOWN'])
        if public_fields!={(x.encode(),typ,0x4019) for x in values}:raise ValueError('unexpected binder enum values')
        if public_methods!={(b'values',b'()['+typ,9),(b'valueOf',b'(Ljava/lang/String;)'+typ,9)}:raise ValueError('unexpected binder enum ABI')
    elif public_methods or public_fields:raise ValueError('unexpected binder internal API')

def check_member_binder_class(clazz,name):
    prefix=b'io/github/jichuo1/dexmeguviz/RuntimeMemberBinder'; old=b'io/github/jichuo1/dexmeguviz/RuntimeMethodBinder'
    enum=name in ('RuntimeMemberBinder$Kind','RuntimeMemberBinder$Status')
    flags=0x4031 if enum else 0x0030 if name=='RuntimeMemberBinder$Context' else 0x0031
    parent=b'java/lang/Enum' if enum else b'java/lang/Object'
    if clazz['flags']!=flags or clazz['superclass']!=parent:raise ValueError('unexpected member binder class flags: '+name)
    methods={(m['name'],m['descriptor'],m['access']) for m in clazz['methods'] if m['access']&1}
    fields={(f['name'],f['descriptor'],f['access']) for f in clazz['fields'] if f['access']&1}
    result=b'L'+prefix+b'$Result;';entity=b'Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityCandidate;';method=b'Lio/github/jichuo1/dexmeguviz/NativeEngine$MethodCandidate;';pre=b'(Ljava/lang/ClassLoader;Ljava/lang/Object;'
    if name=='RuntimeMemberBinder':
        want={(b'bindField',pre+entity+b')'+result,9),(b'bindFieldDescriptor',pre+b'Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;)'+result,9),
              (b'bindConstructor',pre+method+b')'+result,9),(b'bindConstructorDescriptor',pre+b'Ljava/lang/String;Ljava/lang/String;)'+result,9),
              (b'bindClass',pre+entity+b')'+result,9),(b'bindOwnerDescriptor',pre+b'Ljava/lang/String;)'+result,9),(b'bindOwnerAnchor',pre+method+b')'+result,9)}
        if methods!=want or fields:raise ValueError('unexpected member binder API')
    elif name=='RuntimeMemberBinder$Result':
        want={b'kind':b'L'+prefix+b'$Kind;',b'status':b'L'+prefix+b'$Status;',b'origin':b'L'+old+b'$Origin;',
              b'expectedInvocationKind':b'L'+old+b'$InvocationKind;',b'actualInvocationKind':b'L'+old+b'$InvocationKind;',
              b'declaredOwner':b'Ljava/lang/String;',b'name':b'Ljava/lang/String;',b'descriptor':b'Ljava/lang/String;',
              b'initiatingLoader':b'Ljava/lang/ClassLoader;',b'definingLoader':b'Ljava/lang/ClassLoader;',b'definingLoaderKnown':b'Z',b'memberVerified':b'Z',
              b'loaderGeneration':b'Ljava/lang/Object;',b'declaringClass':b'Ljava/lang/Class;',b'constructor':b'Ljava/lang/reflect/Constructor;',
              b'field':b'Ljava/lang/reflect/Field;',b'sourceIndex':b'I',b'inputIndex':b'I',b'sourceSlot':b'Ljava/lang/String;',b'occurrenceId':b'Ljava/lang/String;'}
        if methods!={(b'isForGeneration',b'(Ljava/lang/Object;)Z',1)} or fields!={(n,d,17) for n,d in want.items()}:raise ValueError('unexpected member binder result ABI')
    elif enum:
        typ=b'L'+prefix+(b'$Status;' if name.endswith('$Status') else b'$Kind;')
        names=['BOUND','OWNER_ONLY','INVALID_INPUT','UNSUPPORTED_RELATION','OWNER_NOT_FOUND','SIGNATURE_TYPE_NOT_FOUND','SIGNATURE_MISMATCH','INVOCATION_MISMATCH','AMBIGUOUS','LOADER_ERROR','REFLECTION_ERROR'] if name.endswith('$Status') else ['CONSTRUCTOR','FIELD','OWNER']
        if fields!={(x.encode(),typ,0x4019) for x in names} or methods!={(b'values',b'()['+typ,9),(b'valueOf',b'(Ljava/lang/String;)'+typ,9)}:raise ValueError('unexpected member binder enum ABI')
    elif methods or fields:raise ValueError('unexpected member binder internal API')

def check_apk_fd_class(clazz,name):
    prefix=b'io/github/jichuo1/dexmeguviz/'; interface=name in ('AndroidApkSources$PathOpener','AndroidApkSources$FdOpener')
    flags=0x0600 if interface else 0x0030 if name=='ApkFdInputs' else 0x0031
    if clazz['flags']!=flags or clazz['superclass']!=b'java/lang/Object':raise ValueError('unexpected APK fd class flags: '+name)
    methods={(m['name'],m['descriptor'],m['access']) for m in clazz['methods'] if m['access']&1};fields={(f['name'],f['descriptor'],f['access']) for f in clazz['fields'] if f['access']&1}
    if name=='ApkFdLimits':
        names=['ownedBytes','maxSourceBytes','maxArchiveBytes','maxTotalArchiveBytes','maxDexBytes','maxTotalDexBytes','maxCentralDirectoryBytes','maxTotalNameBytes']
        want={(x.encode(),b'J',17) for x in names}|{(b'maxEntries',b'I',17),(b'MAX_OWNED_BYTES',b'J',25),(b'MAX_SOURCE_BYTES',b'J',25)}
        if fields!=want or methods!={(b'<init>',b'(JJJJJJIJJ)V',1)}:raise ValueError('unexpected APK fd limits ABI')
    elif name=='ApkMetadataPlan':
        decl=b'L'+prefix+b'ApkMetadataPlan$LoaderDeclaration;';result=b'L'+prefix+b'ApkMetadataPlan;'
        want={(b'entries',b'()Ljava/util/List;',1),(b'from',b'(Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;Z[Z)'+result,9),
              (b'from',b'(Ljava/lang/String;'+decl+b'Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;Z[Z)'+result,9)}
        want_fields={(b'packageName',b'Ljava/lang/String;',17),(b'loaderDeclaration',decl,17)}
        if fields!=want_fields or methods!=want:raise ValueError('unexpected APK metadata plan ABI')
    elif name=='ApkMetadataPlan$LoaderDeclaration':
        if fields!={(b'loader',b'Ljava/lang/ClassLoader;',17),(b'generation',b'Ljava/lang/Object;',17)} or methods!={(b'<init>',b'(Ljava/lang/ClassLoader;Ljava/lang/Object;)V',1)}:raise ValueError('unexpected APK loader declaration ABI')
    elif name=='ApkMetadataPlan$Entry':
        want={(x,b'Ljava/lang/String;',17) for x in (b'slot',b'path',b'splitName')}|{(b'allowNoDex',b'Z',17)}
        if fields!=want or methods:raise ValueError('unexpected APK metadata entry ABI')
    elif name=='AndroidApkSources':
        budget=b'L'+prefix+b'ApkFdLimits;';opened=b'L'+prefix+b'AndroidApkSources$Opened;';snapshot=b'L'+prefix+b'NativeEngine$SourceSetSnapshot;'
        decl=b'L'+prefix+b'ApkMetadataPlan$LoaderDeclaration;';plan=b'L'+prefix+b'ApkMetadataPlan;'
        want={(b'plan',b'(Landroid/content/pm/ApplicationInfo;Z[Z)'+plan,9),
              (b'plan',b'(Landroid/content/pm/ApplicationInfo;'+decl+b'Z[Z)'+plan,9),
              (b'open',b'(Landroid/content/pm/ApplicationInfo;Z[Z[Ljava/lang/String;'+budget+b')'+opened,9),
              (b'open',b'(Landroid/content/pm/ApplicationInfo;'+decl+b'Z[Z[Ljava/lang/String;'+budget+b')'+opened,9),
              (b'open',b'('+plan+b'[Ljava/lang/String;'+budget+b')'+opened,9),
              (b'openBorrowed',b'([Landroid/os/ParcelFileDescriptor;[J[J[Ljava/lang/String;[Z[Ljava/lang/String;'+budget+b')'+snapshot,9)}
        if fields or methods!=want:raise ValueError('unexpected Android APK source ABI')
    elif name=='AndroidApkSources$Opened':
        want={(b'plan',b'L'+prefix+b'ApkMetadataPlan;',17),(b'snapshot',b'L'+prefix+b'NativeEngine$SourceSetSnapshot;',17)}
        if fields!=want or methods!={(b'close',b'()V',1)}:raise ValueError('unexpected Android APK result ABI')
    elif name=='AndroidApkSources$PathOpener':
        want={(b'open',b'([[B[Ljava/lang/String;[Z[Ljava/lang/String;L'+prefix+b'ApkFdLimits;)Ljava/lang/AutoCloseable;',0x0401)}
        if fields or methods!=want:raise ValueError('unexpected Android APK path opener ABI')
    elif name=='AndroidApkSources$FdOpener':
        want={(b'open',b'([I[J[J[Ljava/lang/String;[Z[Ljava/lang/String;L'+prefix+b'ApkFdLimits;[Ljava/lang/Object;)Ljava/lang/AutoCloseable;',0x0401)}
        if fields or methods!=want:raise ValueError('unexpected Android APK fd opener ABI')
    elif fields or methods:raise ValueError('unexpected APK fd internal ABI')

def check_method_observation_class(clazz,name):
    prefix=b'io/github/jichuo1/dexmeguviz/'
    if clazz['flags']!=0x0031 or clazz['superclass']!=b'java/lang/Object':raise ValueError('unexpected method observation class flags: '+name)
    methods={(m['name'],m['descriptor'],m['access']) for m in clazz['methods'] if m['access']&1}
    fields={(f['name'],f['descriptor'],f['access']) for f in clazz['fields'] if f['access']&1}
    ref=lambda x:b'L'+prefix+x+b';'
    if name=='MethodSourceObservation':
        want={(b'query',b'('+ref(b'AndroidApkSources$Opened')+b'[B)'+ref(b'MethodSourceObservation$Result'),9)};want_fields=set()
    elif name=='MethodSourceObservation$Result':
        want={(b'observedCandidateCount',b'()I',1),(b'observedCandidate',b'(I)'+ref(b'MethodSourceObservation$Observation'),1)}
        want_fields={(x,b'Ljava/lang/String;',17) for x in (b'snapshotId',b'queryId')}|{(x,b'I',17) for x in (b'executionStatus',b'coverage',b'decision',b'reason',b'visitedMethods',b'totalMethods')}|{(b'unknownRows',b'J',17),(b'sourceScopeComplete',b'Z',17),(b'allInputMethodsScanned',b'Z',17),(b'inputs',ref(b'NativeEngine$SourceSetInfo'),17)}
    elif name=='MethodSourceObservation$Observation':
        want={(b'bind',b'(Ljava/lang/ClassLoader;Ljava/lang/Object;)'+ref(b'RuntimeMethodBinder$Result'),1)}
        want_fields={(x,b'Ljava/lang/String;',17) for x in (b'snapshotId',b'queryId')}|{(b'inputScanIncomplete',b'Z',17),(b'sourceScopeComplete',b'Z',17),(b'input',ref(b'NativeEngine$InputInfo'),17),(b'source',ref(b'NativeEngine$RawDexSourceInfo'),17),(b'candidate',ref(b'NativeEngine$MethodCandidate'),17)}
    else:raise ValueError('unknown observation class')
    if fields!=want_fields or methods!=want:raise ValueError('unexpected method observation ABI: '+name)

def check_caller_relation_class(clazz,name):
    prefix=b'io/github/jichuo1/dexmeguviz/CallerFieldRelationResult'
    enum=name.endswith('$Status');flags=0x4031 if enum else 0x0031;parent=b'java/lang/Enum' if enum else b'java/lang/Object'
    if clazz['flags']!=flags or clazz['superclass']!=parent:raise ValueError('unexpected caller relation class flags: '+name)
    methods={(x['name'],x['descriptor'],x['access']) for x in clazz['methods'] if x['access']&1}
    fields={(x['name'],x['descriptor'],x['access']) for x in clazz['fields'] if x['access']&1}
    if name=='CallerFieldRelationResult':
        want={(b'rowCount',b'()I',1),(b'relation',b'(I)L'+prefix+b'$Relation;',1)};wf={(b'graph',b'Lio/github/jichuo1/dexmeguviz/UseGraphResult;',17)}
    elif name.endswith('$Relation'):
        want={(b'nodeCount',b'()I',1),(b'node',b'(I)L'+prefix+b'$Node;',1),(b'edgeCount',b'()I',1),(b'edge',b'(I)L'+prefix+b'$Edge;',1),(b'interfaceObjectCheckCount',b'()I',1),(b'interfaceObjectCheck',b'(I)L'+prefix+b'$InterfaceObjectCheck;',1)}
        wf={(b'status',b'L'+prefix+b'$Status;',17)}|{(x.encode(),b'J',17) for x in ('reason','callerSource','callerClass','targetSource','targetClass','targetField','eventSource','eventCaller','eventPc')}
    elif name.endswith('$Node'):
        want=set();wf={(x.encode(),b'J',17) for x in ('sourceIndex','classOrdinal','parentIndex','edgeKind','interfaceIndex')}
    elif name.endswith('$Edge'):
        want=set();wf={(x.encode(),b'I',17) for x in ('from','to')}|{(x.encode(),b'J',17) for x in ('kind','interfaceIndex')}
    elif name.endswith('$InterfaceObjectCheck'):
        want=set();wf={(b'interfaceNode',b'I',17),(b'objectSource',b'J',17),(b'objectClass',b'J',17)}
    else:
        typ=b'L'+prefix+b'$Status;';want={(b'values',b'()['+typ,9),(b'valueOf',b'(Ljava/lang/String;)'+typ,9)};wf={(x,typ,0x4019) for x in (b'SELF',b'ANCESTOR',b'EXTERNAL',b'UNKNOWN')}
    if fields!=wf or methods!=want:raise ValueError('unexpected caller relation public ABI: '+name)


PRECOMPUTE_CLASSES = ['Budget', 'LocalCertificates', 'LocalCertificates$Context', 'LocalDex', 'LocalDex$Cursor', 'OfflineJson', 'OfflineJson$Parser', 'OpcodeWidths', 'PrecomputedCandidates', 'PrecomputedCandidates$Candidate', 'PrecomputedCandidates$Failure', 'PrecomputedCandidates$Limits', 'PrecomputedCandidates$Result', 'PrecomputedCandidates$Rule', 'PrecomputedCandidates$Source', 'PrecomputedCandidates$SourceInput', 'SourceCatalog', 'SourceCatalog$Digest', 'SourceCatalog$Entry', 'SourceCatalog$Input']

TRUSTED_APK_SOURCE_CLASSES=['TrustedApkDexSource','TrustedApkDexSource$Policy','TrustedApkDexSource$Limits',
    'TrustedApkDexSource$Input','TrustedApkDexSource$SourceSetLimits','TrustedApkDexSource$Mapper',
    'TrustedApkDexSource$Entry','TrustedApkDexSource$SourceResult','TrustedApkDexSource$Result',
    'TrustedApkDexSource$SourceSetResult','TrustedApkDexSource$Task','TrustedApkDexSource$Indexed','TrustedApkDexSource$OpenInput',
    'TrustedApkDexSource$OpenArchives']
PARALLEL_DEX_QUERY_CLASSES=['ParallelDexQuery','ParallelDexQuery$1','ParallelDexQuery$Kind',
    'ParallelDexQuery$Rule','ParallelDexQuery$RuleResult','ParallelDexQuery$SourceMapper']

PARALLEL_FAST_QUERY_CLASSES=['ParallelFastDexQuery','ParallelFastDexQuery$1']

NATIVE_APK_FAST_CLASSES=['NativeApkFastQuery','NativeApkFastQuery$Policy','NativeApkFastQuery$Input',
    'NativeApkFastQuery$SourceLimits','NativeApkFastQuery$InputSummary','NativeApkFastQuery$SourceResult','NativeApkFastQuery$Result']

def check_native_apk_fast_class(clazz,name):
    if name not in NATIVE_APK_FAST_CLASSES:raise ValueError('unknown native APK query class')
    policy=name.endswith('$Policy'); synthetic=name.endswith('$1')
    if clazz['flags']!=(0x1020 if synthetic else 0x4031 if policy else 0x0031) or clazz['superclass']!=(b'java/lang/Enum' if policy else b'java/lang/Object'):
        raise ValueError('native APK query class identity: '+name)
    if any(m['access']&0x0100 for m in clazz['methods']):raise ValueError('native APK wrapper must not declare JNI')
    p=b'io/github/jichuo1/dexmeguviz/';n=p+b'NativeApkFastQuery';f=p+b'FastDexQuery'
    methods={(m['name'],m['descriptor'],m['access']) for m in clazz['methods'] if m['access']&1}
    fields={(x['name'],x['descriptor'],x['access']) for x in clazz['fields'] if x['access']&1}
    want=set();wf=set()
    if name=='NativeApkFastQuery':
        want={(b'queryAll',b'(Ljava/util/List;L'+n+b'$Policy;L'+f+b'$InputAssumption;L'+n+b'$SourceLimits;L'+f+b'$Limits;L'+f+b'$Plans;ZI)L'+n+b'$Result;',9)}
    elif name.endswith('$Policy'):
        t=b'L'+n+b'$Policy;';want={(b'values',b'()['+t,9),(b'valueOf',b'(Ljava/lang/String;)'+t,9)};wf={(b'TRUSTED_IMMUTABLE_APK',t,0x4019)}
    elif name.endswith('$Input'):
        want={(b'<init>',b'(Ljava/io/File;Ljava/lang/String;Z)V',1)};wf={(b'apk',b'Ljava/io/File;',17),(b'slot',b'Ljava/lang/String;',17),(b'allowNoDex',b'Z',17)}
    elif name.endswith('$SourceLimits'):
        want={(b'<init>',b'(IIIIIJJJJJJJJ)V',1)}
        wf={(x.encode(),b'I',17) for x in ('workers','maxInputs','maxSourcesPerInput','maxSources','maxEntries')}|{(x.encode(),b'J',17) for x in ('maxArchivePerInput','maxArchiveTotal','maxDexPerInput','maxDexTotal','maxOneDex','maxInflight','maxZipMetadata','maxRowsAggregate')}
    elif name.endswith('$InputSummary'):
        wf={(b'slot',b'Ljava/lang/String;',17),(b'sourceCount',b'I',17)}|{(x.encode(),b'J',17) for x in ('archiveBytes','dexBytes','compressedBytes')}
    elif name.endswith('$SourceResult'):
        wf={(x.encode(),b'Ljava/lang/String;',17) for x in ('slot','matchedSha256')}|{(x.encode(),b'I',17) for x in ('inputIndex','centralIndex','ordinal')}|{(x.encode(),b'J',17) for x in ('size','compressedSize','crc')}|{(b'result',b'L'+f+b'$Result;',17)}
    elif name.endswith('$Result'):
        wf={(x.encode(),b'Ljava/util/List;',17) for x in ('inputs','ordered')}
    if methods!=want or fields!=wf:raise ValueError('unexpected native APK public ABI: '+name)


def check_parallel_fast_query_class(clazz,name):
    if name not in PARALLEL_FAST_QUERY_CLASSES:raise ValueError('unknown parallel fast query class')
    flags=0x0020 if name.endswith('$1') else 0x0031
    parent=b'java/lang/ThreadLocal' if name.endswith('$1') else b'java/lang/Object'
    if clazz['flags']!=flags or clazz['superclass']!=parent:raise ValueError('parallel fast query class identity: '+name)
    if any(m['access']&0x0100 for m in clazz['methods']):raise ValueError('parallel fast wrapper must not declare JNI')
    if name=='ParallelFastDexQuery':
        p=b'io/github/jichuo1/dexmeguviz/';s=p+b'TrustedApkDexSource';f=p+b'FastDexQuery'
        methods={(m['name'],m['descriptor'],m['access']) for m in clazz['methods'] if m['access']&1}
        want={(b'query',b'(Ljava/io/File;Ljava/lang/String;L'+s+b'$Policy;L'+s+b'$Limits;L'+f+b'$InputAssumption;L'+f+b'$Limits;[[B[Z)L'+s+b'$Result;',9),
              (b'queryAll',b'(Ljava/util/List;L'+s+b'$Policy;L'+s+b'$SourceSetLimits;L'+f+b'$InputAssumption;L'+f+b'$Limits;[[B[Z)L'+s+b'$SourceSetResult;',9)}
        if methods!=want:raise ValueError('parallel fast query entry ABI')

def check_parallel_dex_query_class(clazz,name):
    if name not in PARALLEL_DEX_QUERY_CLASSES:raise ValueError('unknown parallel DEX class')
    flags=0x0020 if name.endswith('$1') else 0x0601 if name.endswith('$SourceMapper') else 0x4031 if name.endswith('$Kind') else 0x0031
    parent=b'java/lang/ThreadLocal' if name.endswith('$1') else b'java/lang/Enum' if name.endswith('$Kind') else b'java/lang/Object'
    if clazz['flags']!=flags or clazz['superclass']!=parent:raise ValueError('parallel DEX class identity: '+name)
    if any(m['access']&0x0100 for m in clazz['methods']):raise ValueError('parallel DEX wrapper must not declare JNI')
    prefix=b'io/github/jichuo1/dexmeguviz/'
    methods={(m['name'],m['descriptor'],m['access']) for m in clazz['methods'] if m['access']&1}
    if name=='ParallelDexQuery':
        source=prefix+b'TrustedApkDexSource';mapper=b'L'+prefix+b'ParallelDexQuery$SourceMapper;'
        want={(b'map',b'(Ljava/io/File;Ljava/lang/String;L'+source+b'$Policy;L'+source+b'$Limits;Ljava/util/List;JZJJ'+mapper+b')L'+source+b'$Result;',9),
              (b'mapAll',b'(Ljava/util/List;L'+source+b'$Policy;L'+source+b'$SourceSetLimits;Ljava/util/List;JZJJ'+mapper+b')L'+source+b'$SourceSetResult;',9)}
        if methods!=want:raise ValueError('parallel DEX entry ABI')
    if name.endswith('$SourceMapper'):
        want={(b'map',b'(L'+prefix+b'TrustedApkDexSource$Entry;L'+prefix+b'NativeEngine$Snapshot;Ljava/util/List;)Ljava/lang/Object;',0x0401)}
        if methods!=want:raise ValueError('parallel DEX mapper ABI')
    if name.endswith('$Rule'):
        typ=b'L'+prefix+b'ParallelDexQuery$Rule;';kind=b'L'+prefix+b'ParallelDexQuery$Kind;'
        if methods!={(b'method',b'([B)'+typ,9),(b'reflectionMethodUses',b'([B)'+typ,9),(b'kind',b'()'+kind,1)}:
            raise ValueError('parallel DEX rule ABI')

def check_trusted_apk_source_class(clazz,name):
    if name not in TRUSTED_APK_SOURCE_CLASSES:raise ValueError('unknown trusted APK source class')
    private=name in ('TrustedApkDexSource$Task','TrustedApkDexSource$Indexed','TrustedApkDexSource$OpenInput','TrustedApkDexSource$OpenArchives')
    flags=0x0601 if name.endswith('$Mapper') else 0x4031 if name.endswith('$Policy') else 0x0030 if private else 0x0031
    parent=b'java/lang/Enum' if name.endswith('$Policy') else b'java/lang/Object'
    if clazz['flags']!=flags or clazz['superclass']!=parent:raise ValueError('trusted APK class identity: '+name)
    if any(m['access']&0x0100 for m in clazz['methods']):raise ValueError('trusted APK source must not declare JNI')
    prefix=b'io/github/jichuo1/dexmeguviz/TrustedApkDexSource'
    methods={(m['name'],m['descriptor'],m['access']) for m in clazz['methods'] if m['access']&1}
    if name=='TrustedApkDexSource':
        want={(b'map',b'(Ljava/io/File;Ljava/lang/String;L'+prefix+b'$Policy;L'+prefix+b'$Limits;L'+prefix+b'$Mapper;)L'+prefix+b'$Result;',9),
              (b'mapAll',b'(Ljava/util/List;L'+prefix+b'$Policy;L'+prefix+b'$SourceSetLimits;L'+prefix+b'$Mapper;)L'+prefix+b'$SourceSetResult;',9)}
        if methods!=want:raise ValueError('trusted APK source entry ABI')
    if name.endswith('$Mapper') and methods!={(b'apply',b'(L'+prefix+b'$Entry;[B)Ljava/lang/Object;',0x0401)}:
        raise ValueError('trusted APK source mapper ABI')
    public_fields={(f['name'],f['descriptor'],f['access']) for f in clazz['fields'] if f['access']&1}
    if name.endswith('$Entry'):
        want={(x,b'Ljava/lang/String;',17) for x in (b'inputSlot',b'name')}|{(x,b'I',17) for x in (b'inputIndex',b'centralIndex',b'ordinal')}|{(x,b'J',17) for x in (b'size',b'crc')}
        if public_fields!=want:raise ValueError('trusted APK source occurrence ABI')
    if name.endswith('$SourceResult') and public_fields!={(b'source',b'L'+prefix+b'$Entry;',17),(b'value',b'Ljava/lang/Object;',17)}:
        raise ValueError('trusted APK source result ABI')
    if name.endswith('$Input'):
        if methods!={(b'<init>',b'(Ljava/io/File;Ljava/lang/String;Z)V',1)} or public_fields!={(b'apk',b'Ljava/io/File;',17),(b'slot',b'Ljava/lang/String;',17),(b'allowNoDex',b'Z',17)}:
            raise ValueError('trusted APK input ABI')
    if name.endswith('$Limits'):
        want={(x,b'I',17) for x in (b'workers',b'maxSources',b'maxDexBytes',b'maxZipEntries')}|{(x,b'J',17) for x in (b'maxArchiveBytes',b'maxTotalDexBytes')}|{(b'allowNoDex',b'Z',17)}
        if methods!={(b'<init>',b'(IIIIJJ)V',1),(b'<init>',b'(IIIIJJZ)V',1)} or public_fields!=want:raise ValueError('trusted APK limits ABI')
    if name.endswith('$SourceSetLimits'):
        want={(b'perInput',b'L'+prefix+b'$Limits;',17)}|{(x,b'I',17) for x in (b'maxInputs',b'maxTotalSources')}|{(x,b'J',17) for x in (b'maxTotalArchiveBytes',b'maxTotalDexBytes')}
        if methods!={(b'<init>',b'(L'+prefix+b'$Limits;IIJJ)V',1)} or public_fields!=want:raise ValueError('trusted APK source-set limits ABI')
    if name.endswith('$Result'):
        want={(b'inputSlot',b'Ljava/lang/String;',17),(b'inputIndex',b'I',17),(b'archiveBytes',b'J',17),(b'allowNoDex',b'Z',17),(b'ordered',b'Ljava/util/List;',17),(b'sources',b'I',17),(b'dexBytes',b'J',17),(b'compressedBytes',b'J',17)}
        if public_fields!=want:raise ValueError('trusted APK input result ABI')
    if name.endswith('$SourceSetResult'):
        want={(x,b'Ljava/util/List;',17) for x in (b'inputs',b'ordered')}|{(x,b'J',17) for x in (b'archiveBytes',b'dexBytes',b'compressedBytes')}|{(b'sources',b'I',17)}
        if public_fields!=want:raise ValueError('trusted APK source-set result ABI')

def check_precompute_class(clazz,name):
    short=name.removeprefix('precompute/')
    if short not in PRECOMPUTE_CLASSES:raise ValueError('unknown offline consumer class')
    public=short=='PrecomputedCandidates' or short.startswith('PrecomputedCandidates$')
    expected_parent=b'java/lang/RuntimeException' if short=='PrecomputedCandidates$Failure' else b'java/lang/Object'
    if clazz['flags']!=(0x0031 if public else 0x0030) or clazz['superclass']!=expected_parent:raise ValueError('offline consumer class identity')
    if any(m['access']&0x0100 for m in clazz['methods']):raise ValueError('offline consumer must not declare JNI')
    prefix=b'io/github/jichuo1/dexmeguviz/precompute/'
    if short=='PrecomputedCandidates':
        actual={(m['descriptor'],m['access']) for m in clazz['methods'] if m['name']==b'consume'}
        wanted={(b'([B[BLjava/lang/String;ZLjava/util/List;)L'+prefix+b'PrecomputedCandidates$Result;',9),(b'([B[BLjava/lang/String;ZLjava/util/List;L'+prefix+b'PrecomputedCandidates$Limits;)L'+prefix+b'PrecomputedCandidates$Result;',9)}
        if actual!=wanted:raise ValueError('offline consumer entry ABI')

def check_kotlin_class(clazz,name):
    prefix=b'io/github/jichuo1/dexmeguviz/'
    enums={'GraphIdentity','GraphJoinKey','GraphSetSemantics','GraphRolePolicy','Coverage','Decision','DecisionReason','ExecutionStatus','MethodTextField','QueryIntent','RawFlagOperation','TextOperation','EntityRelation','EntityTextField','InvokeReferenceKind','FieldUseAccess','FieldDeclarationScope','TypeUseOpcode','TypeUseJoinTarget','TypeUseJoinDirection','TypeUseJoinKind'}
    enums.update({'ExpandDirection','ExpandOutput'})
    enums.update({'UseSymbolTarget','UseSymbolDirection','UseSymbolJoin','UseEventTextField','UseEventNumberField','UseEventTargetDomain','UseReferenceTarget'})
    if b'Lkotlin/Metadata;' not in clazz['utf_indexes']:raise ValueError('Kotlin metadata marker missing: '+name)
    expected_flags=0x4031 if name in enums else 0x1031 if name in ('GraphExpression$Companion$WhenMappings','FieldDeclarationQuery$WhenMappings') else 0x0031
    expected_parent=b'java/lang/Enum' if name in enums else b'java/lang/Object'
    if clazz['flags']!=expected_flags or clazz['superclass']!=expected_parent:raise ValueError('unexpected Kotlin class access/superclass: '+name)
    if name in ('ReflectionMethodUsesExecution','TypedReflectionMethodUsesExecution','TypedUseTargetReferenceExecution','TypedInvokeSiteExecution','ScopedUseGraphExecution','FieldDeclarationQueryExecution','TypedFieldDeclarationCallerExecution','CallerFieldRelationExecution','ClassAnnotationGraphExecution','TypeUseExecution','MethodTypeExecution','ExpandExecution','AdvancedExecution','InheritedUseGraphExecution','InterfaceUseGraphExecution','MethodFactsExecution','MethodParametersExecution','AnnotationExecution','DexSourceExportExecution'):
        fields=[f for f in clazz['fields'] if f['name']==b'INSTANCE']
        if len(fields)!=1 or fields[0]['descriptor']!=b'L'+prefix+name.encode('ascii')+b';' or fields[0]['access']!=0x0019:
            raise ValueError('Kotlin singleton INSTANCE mismatch: '+name)
    if name=='ReflectionMethodPredicate':
        fields=[f for f in clazz['fields'] if f['name']==b'Companion']
        if len(fields)!=1 or fields[0]['descriptor']!=b'L'+prefix+b'ReflectionMethodPredicate$Companion;' or fields[0]['access']!=0x0019:
            raise ValueError('Kotlin companion field mismatch: '+name)
    anchors={
      'MethodPredicate$Companion':(b'text',b'(Lio/github/jichuo1/dexmeguviz/MethodTextField;Lio/github/jichuo1/dexmeguviz/TextOperation;Ljava/lang/String;Z)Lio/github/jichuo1/dexmeguviz/MethodPredicate;',0x0011),
      'MethodPredicate':(b'<init>',b'(Ljava/lang/String;Lkotlin/jvm/internal/DefaultConstructorMarker;)V',0x1001),
      'MethodQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',0x0011),
      'QueryExecution':(b'execute',b'(Lio/github/jichuo1/dexmeguviz/MethodQuery;)Ljava/lang/Void;',0x0011),
      'GraphQueryExecution':(b'<init>',b'()V',0x0002),
      'QuerySummary':(b'getCoverage',b'()Lio/github/jichuo1/dexmeguviz/Coverage;',0x0011),
      'RawDexFlags':(b'getBits',b'()J',0x0011),
      'SourceIdentity':(b'getOccurrenceId',b'()Ljava/lang/String;',0x0011),
      'EntityPredicate$Companion':(b'text',b'(Lio/github/jichuo1/dexmeguviz/EntityTextField;Lio/github/jichuo1/dexmeguviz/TextOperation;Ljava/lang/String;Z)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
      'EntityPredicate':(b'<init>',b'(Lio/github/jichuo1/dexmeguviz/MethodPredicate;ILkotlin/jvm/internal/DefaultConstructorMarker;)V',0x1001),
      'EntityQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',0x0011),
    }
    anchors['ReflectionMethodUsesExecution']=(b'<init>',b'()V',0x0002)
    anchors.update({
      'StaticTextMatch':(b'<init>',b'(Lio/github/jichuo1/dexmeguviz/TextOperation;Ljava/lang/String;Z)V',0x0001),
      'InvokeTarget':(b'<init>',b'(Lio/github/jichuo1/dexmeguviz/StaticTextMatch;Lio/github/jichuo1/dexmeguviz/StaticTextMatch;Lio/github/jichuo1/dexmeguviz/StaticTextMatch;Lio/github/jichuo1/dexmeguviz/StaticTextMatch;Ljava/lang/Long;Ljava/lang/Long;Lio/github/jichuo1/dexmeguviz/InvokeReferenceKind;)V',0x0001),
      'FieldTarget':(b'<init>',b'(Lio/github/jichuo1/dexmeguviz/StaticTextMatch;Lio/github/jichuo1/dexmeguviz/StaticTextMatch;Lio/github/jichuo1/dexmeguviz/StaticTextMatch;Lio/github/jichuo1/dexmeguviz/FieldUseAccess;)V',0x0001),
      'ReflectionMethodPredicate':(b'<init>',b'(Ljava/lang/String;ZZLkotlin/jvm/internal/DefaultConstructorMarker;)V',0x1001),
      'ReflectionMethodPredicate$Companion':(b'metadata',b'(Lio/github/jichuo1/dexmeguviz/MethodPredicate;)Lio/github/jichuo1/dexmeguviz/ReflectionMethodPredicate;',0x0011),
      'ReflectionMethodUsesQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',0x0011),
      'ReflectionMethodUsesQueryKt':(b'boundedJoin',b'(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;',0x001a),
      'TypedReflectionMethodUsesExecution':(b'<init>',b'()V',0x0002),
    })
    if name in ('GraphExpression$Companion$WhenMappings','FieldDeclarationQuery$WhenMappings'): return
    anchors.update({'GraphExpression': (b'getRelation', b'()Lio/github/jichuo1/dexmeguviz/EntityRelation;', 17), 'GraphExpression$Companion': (b'scan', b'(Lio/github/jichuo1/dexmeguviz/EntityRelation;Lio/github/jichuo1/dexmeguviz/GraphPredicate;)Lio/github/jichuo1/dexmeguviz/GraphExpression;', 17), 'GraphPredicate': (b'<init>', b'(Ljava/lang/String;IZLkotlin/jvm/internal/DefaultConstructorMarker;)V', 4097), 'GraphPredicate$Companion': (b'from', b'(Lio/github/jichuo1/dexmeguviz/EntityPredicate;)Lio/github/jichuo1/dexmeguviz/GraphPredicate;', 17), 'GraphQuery': (b'toQueryIrJson', b'()Ljava/lang/String;', 17), 'ReflectionFlags': (b'getBits', b'()J', 17), 'TypedGraphQueryExecution': (b'<init>', b'()V', 2), 'UseGraphQueryExecution': (b'<init>', b'()V', 2)})
    anchors.update({'UseEventPredicate': (b'<init>', b'(Ljava/lang/String;ILkotlin/jvm/internal/DefaultConstructorMarker;)V', 4097), 'UseEventPredicate$Companion': (b'constant', b'(Z)Lio/github/jichuo1/dexmeguviz/UseEventPredicate;', 17), 'UseTargetSymbolQuery': (b'toQueryIrJson', b'()Ljava/lang/String;', 17), 'TypedUseTargetSymbolExecution': (b'<init>', b'()V', 2)})
    anchors.update({'UseTargetReferenceQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',0x0011),'TypedUseTargetReferenceExecution':(b'<init>',b'()V',0x0002)})
    anchors.update({'InvokeSiteQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',0x0011),'TypedInvokeSiteExecution':(b'<init>',b'()V',0x0002)})
    anchors.update({'ScopedInvokeSiteQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',0x0011),'ScopedUseGraphExecution':(b'<init>',b'()V',0x0002)})
    anchors.update({'FieldDeclarationQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',0x0011),'FieldDeclarationQueryExecution':(b'<init>',b'()V',0x0002)})
    anchors.update({'FieldDeclarationCallerQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',0x0011),'TypedFieldDeclarationCallerExecution':(b'<init>',b'()V',0x0002)})
    anchors.update({'CallerFieldRelationQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',0x0011),'CallerFieldRelationExecution':(b'<init>',b'()V',0x0002)})
    anchors.update({'ClassAnnotationGraphQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',17),'ClassAnnotationGraphExecution':(b'<init>',b'()V',2)})
    anchors.update({'TypeUsePredicate':(b'<init>',b'(Ljava/lang/String;Lkotlin/jvm/internal/DefaultConstructorMarker;)V',4097),'TypeUsePredicate$Companion':(b'constant',b'(Z)L'+prefix+b'TypeUsePredicate;',17),'TypeUseQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',17),'TypeUseExecution':(b'<init>',b'()V',2)})
    anchors.update({'AdvancedQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',17),'AdvancedExecution':(b'<init>',b'()V',2)})
    anchors.update({'InheritedUseGraphExecution':(b'<init>',b'()V',2)})
    anchors.update({'MethodFactsRequest':(b'getCategories',b'()Ljava/util/Set;',17),'MethodFactsExecution':(b'<init>',b'()V',2)})
    anchors.update({'MethodParametersLimits':(b'<init>',b'(IIJJ)V',1),'MethodParametersExecution':(b'<init>',b'()V',2)})
    anchors.update({'AnnotationExecution':(b'<init>',b'()V',2),'DexSourceExportExecution':(b'<init>',b'()V',2)})
    anchors.update({'InterfaceUseGraphExecution':(b'<init>',b'()V',2)})
    anchors.update({'MethodTypeTarget':(b'getDescriptor',b'()L'+prefix+b'StaticTextMatch;',17),'MethodTypePredicate':(b'<init>',b'(Ljava/lang/String;ZLkotlin/jvm/internal/DefaultConstructorMarker;)V',4097),'MethodTypePredicate$Companion':(b'metadata',b'(L'+prefix+b'MethodPredicate;)L'+prefix+b'MethodTypePredicate;',17),'MethodTypeQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',17),'MethodTypeExecution':(b'<init>',b'()V',2),'MethodTypeQueryKt':(b'methodTypeJoin',b'(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;',26)})
    anchors.update({'ExpandQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',17),'ExpandGraphQuery':(b'toQueryIrJson',b'()Ljava/lang/String;',17),'ExpandExecution':(b'<init>',b'()V',2)})
    if name in enums:expected=(b'values',b'()[L'+prefix+name.encode('ascii')+b';',0x0009)
    else:expected=anchors[name]
    method=[m for m in clazz['methods'] if (m['name'],m['descriptor'])==expected[:2]]
    if len(method)!=1 or method[0]['access']!=expected[2] or sum(a[0]==b'Code' for a in method[0]['attributes'])!=1:
        raise ValueError('Kotlin anchor method mismatch: '+name)
    entity_enum_members={
      'EntityRelation':{b'METHOD_DEFS',b'CLASS_DEFS',b'FIELD_DEFS',b'METHOD_REFS',b'FIELD_REFS',b'TYPE_REFS',b'STRING_VALUES'},
      'EntityTextField':{b'NAME',b'OWNER',b'PROTOTYPE',b'RETURN_TYPE',b'DESCRIPTOR',b'TYPE',b'VALUE',b'SUPERCLASS',b'DIRECT_INTERFACE'},
    }
    entity_enum_members.update({'GraphIdentity': {b'ENTITY', b'TUPLE'}, 'GraphJoinKey': {b'SAME_ENTITY', b'LOCAL_DEFINITION', b'LOCAL_OWNER', b'SYMBOL'}, 'GraphSetSemantics': {b'SET', b'BAG'}, 'GraphRolePolicy': {b'SHARED', b'DISTINCT'}})
    entity_enum_members.update({'InvokeReferenceKind':{b'METHOD_LIKE',b'METHOD',b'METHOD_AND_PROTO',b'CALL_SITE'},'FieldUseAccess':{b'ANY',b'READ',b'WRITE'}})
    entity_enum_members['UseReferenceTarget']={b'METHOD_REFERENCE',b'FIELD_REFERENCE',b'STRING_VALUE'}
    entity_enum_members['FieldDeclarationScope']={b'DECLARED',b'INHERITED',b'ANY'}
    entity_enum_members.update({'ExpandDirection':{b'OUTGOING',b'INCOMING'},'ExpandOutput':{b'PATHS',b'ENDPOINTS'}})
    if name in entity_enum_members:
        fields=[f for f in clazz['fields'] if f['access']&0x4000]
        if (len(fields)!=len(entity_enum_members[name]) or {f['name'] for f in fields}!=entity_enum_members[name] or
            any(f['descriptor']!=b'L'+prefix+name.encode('ascii')+b';' or f['access']!=0x4019 for f in fields)):
            raise ValueError('Kotlin entity enum mismatch: '+name)
    extra={
      'MethodPredicate$Companion':[(b'textValue',b'(Lio/github/jichuo1/dexmeguviz/MethodTextField;Lio/github/jichuo1/dexmeguviz/TextOperation;Ljava/lang/String;Z)Lio/github/jichuo1/dexmeguviz/MethodPredicate;',0x0011),
        (b'ownerFlags',b'(Lio/github/jichuo1/dexmeguviz/RawFlagOperation;Lio/github/jichuo1/dexmeguviz/RawDexFlags;)Lio/github/jichuo1/dexmeguviz/MethodPredicate;',0x0011),
        (b'parameterCount',b'(J)Lio/github/jichuo1/dexmeguviz/MethodPredicate;',0x0011),
        (b'parameterCount',b'(JJ)Lio/github/jichuo1/dexmeguviz/MethodPredicate;',0x0011),
        (b'parameter',b'(JLio/github/jichuo1/dexmeguviz/TextOperation;Ljava/lang/String;Z)Lio/github/jichuo1/dexmeguviz/MethodPredicate;',0x0011),
        (b'usesString',b'(Lio/github/jichuo1/dexmeguviz/TextOperation;Ljava/lang/String;Z)Lio/github/jichuo1/dexmeguviz/MethodPredicate;',0x0011),
        (b'constructor',b'()Lio/github/jichuo1/dexmeguviz/MethodPredicate;',0x0011),
        (b'classInitializer',b'()Lio/github/jichuo1/dexmeguviz/MethodPredicate;',0x0011),
        (b'normalMethod',b'()Lio/github/jichuo1/dexmeguviz/MethodPredicate;',0x0011)],
      'EntityPredicate$Companion':[
        (b'textValue',b'(Lio/github/jichuo1/dexmeguviz/EntityTextField;Lio/github/jichuo1/dexmeguviz/TextOperation;Ljava/lang/String;Z)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'flags',b'(Lio/github/jichuo1/dexmeguviz/RawFlagOperation;Lio/github/jichuo1/dexmeguviz/RawDexFlags;)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'ownerFlags',b'(Lio/github/jichuo1/dexmeguviz/RawFlagOperation;Lio/github/jichuo1/dexmeguviz/RawDexFlags;)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'hasLocalDefinition',b'(Z)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'parameterCount',b'(J)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'parameterCount',b'(JJ)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'parameter',b'(JLio/github/jichuo1/dexmeguviz/TextOperation;Ljava/lang/String;Z)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'constructor',b'()Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'classInitializer',b'()Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'normalMethod',b'()Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'constant',b'(Z)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'not',b'(Lio/github/jichuo1/dexmeguviz/EntityPredicate;)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0011),
        (b'all',b'([Lio/github/jichuo1/dexmeguviz/EntityPredicate;)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0091),
        (b'any',b'([Lio/github/jichuo1/dexmeguviz/EntityPredicate;)Lio/github/jichuo1/dexmeguviz/EntityPredicate;',0x0091)],
      'EntityQuery':[(b'<init>',b'(Lio/github/jichuo1/dexmeguviz/EntityRelation;Lio/github/jichuo1/dexmeguviz/EntityPredicate;Lio/github/jichuo1/dexmeguviz/QueryIntent;IJ)V',0x0001)],
      'GraphQueryExecution':[(b'startGraphJob',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;[BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$GraphJob;',0x0011),
                             (b'startGraphJob',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;[BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$GraphJob;',0x0011),
                             (b'execute',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;[B)Lio/github/jichuo1/dexmeguviz/GraphResult;',0x0011),
                             (b'execute',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;[B)Lio/github/jichuo1/dexmeguviz/GraphResult;',0x0011)],
      'QueryExecution':[(b'startMethodJob',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;Lio/github/jichuo1/dexmeguviz/MethodQuery;IIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$Job;',0x0011),
                        (b'startMethodJob',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;Lio/github/jichuo1/dexmeguviz/MethodQuery;IIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$Job;',0x0011),
                        (b'execute',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;Lio/github/jichuo1/dexmeguviz/MethodQuery;)Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;',0x0011),
                        (b'execute',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;Lio/github/jichuo1/dexmeguviz/MethodQuery;)Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;',0x0011),
                        (b'execute',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;Lio/github/jichuo1/dexmeguviz/EntityQuery;)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;',0x0011),
                        (b'execute',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;Lio/github/jichuo1/dexmeguviz/EntityQuery;)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;',0x0011),
                        (b'startEntityJob',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;Lio/github/jichuo1/dexmeguviz/EntityQuery;IIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0011),
                        (b'startEntityJob',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;Lio/github/jichuo1/dexmeguviz/EntityQuery;IIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0011)],
    }
    extra.update({'GraphExpression': [(b'getRelation', b'()Lio/github/jichuo1/dexmeguviz/EntityRelation;', 17)], 'GraphExpression$Companion': [(b'scan', b'(Lio/github/jichuo1/dexmeguviz/EntityRelation;Lio/github/jichuo1/dexmeguviz/GraphPredicate;)Lio/github/jichuo1/dexmeguviz/GraphExpression;', 17), (b'filter', b'(Lio/github/jichuo1/dexmeguviz/GraphExpression;Lio/github/jichuo1/dexmeguviz/GraphPredicate;)Lio/github/jichuo1/dexmeguviz/GraphExpression;', 17), (b'label', b'(Lio/github/jichuo1/dexmeguviz/GraphExpression;Ljava/lang/String;)Lio/github/jichuo1/dexmeguviz/GraphExpression;', 17), (b'union', b'(Lio/github/jichuo1/dexmeguviz/GraphSetSemantics;Lio/github/jichuo1/dexmeguviz/GraphIdentity;[Lio/github/jichuo1/dexmeguviz/GraphExpression;)Lio/github/jichuo1/dexmeguviz/GraphExpression;', 145), (b'distinct', b'(Lio/github/jichuo1/dexmeguviz/GraphExpression;Lio/github/jichuo1/dexmeguviz/GraphIdentity;)Lio/github/jichuo1/dexmeguviz/GraphExpression;', 17), (b'join', b'(Lio/github/jichuo1/dexmeguviz/GraphExpression;Lio/github/jichuo1/dexmeguviz/GraphExpression;Lio/github/jichuo1/dexmeguviz/GraphJoinKey;)Lio/github/jichuo1/dexmeguviz/GraphExpression;', 17), (b'semiJoin', b'(Lio/github/jichuo1/dexmeguviz/GraphExpression;Lio/github/jichuo1/dexmeguviz/GraphExpression;Lio/github/jichuo1/dexmeguviz/GraphJoinKey;)Lio/github/jichuo1/dexmeguviz/GraphExpression;', 17), (b'groupByOwner', b'(Ljava/util/List;JJLjava/util/List;Lio/github/jichuo1/dexmeguviz/GraphRolePolicy;)Lio/github/jichuo1/dexmeguviz/GraphExpression;', 17)], 'GraphPredicate': [], 'GraphPredicate$Companion': [(b'from', b'(Lio/github/jichuo1/dexmeguviz/EntityPredicate;)Lio/github/jichuo1/dexmeguviz/GraphPredicate;', 17), (b'constant', b'(Z)Lio/github/jichuo1/dexmeguviz/GraphPredicate;', 17), (b'reflectionFlags', b'(Lio/github/jichuo1/dexmeguviz/RawFlagOperation;Lio/github/jichuo1/dexmeguviz/ReflectionFlags;)Lio/github/jichuo1/dexmeguviz/GraphPredicate;', 17), (b'reflectionOwnerFlags', b'(Lio/github/jichuo1/dexmeguviz/RawFlagOperation;Lio/github/jichuo1/dexmeguviz/ReflectionFlags;)Lio/github/jichuo1/dexmeguviz/GraphPredicate;', 17), (b'not', b'(Lio/github/jichuo1/dexmeguviz/GraphPredicate;)Lio/github/jichuo1/dexmeguviz/GraphPredicate;', 17), (b'all', b'([Lio/github/jichuo1/dexmeguviz/GraphPredicate;)Lio/github/jichuo1/dexmeguviz/GraphPredicate;', 145), (b'any', b'([Lio/github/jichuo1/dexmeguviz/GraphPredicate;)Lio/github/jichuo1/dexmeguviz/GraphPredicate;', 145)], 'GraphQuery': [(b'<init>', b'(Lio/github/jichuo1/dexmeguviz/GraphExpression;Lio/github/jichuo1/dexmeguviz/QueryIntent;IJ)V', 1), (b'getRelation', b'()Lio/github/jichuo1/dexmeguviz/GraphExpression;', 17), (b'getIntent', b'()Lio/github/jichuo1/dexmeguviz/QueryIntent;', 17), (b'getMaxResults', b'()I', 17), (b'getMaxWork', b'()J', 17), (b'toQueryIrJson', b'()Ljava/lang/String;', 17)], 'ReflectionFlags': [(b'<init>', b'(J)V', 1), (b'getBits', b'()J', 17)], 'TypedGraphQueryExecution': [(b'execute', b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;Lio/github/jichuo1/dexmeguviz/GraphQuery;)Lio/github/jichuo1/dexmeguviz/GraphResult;', 17), (b'execute', b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;Lio/github/jichuo1/dexmeguviz/GraphQuery;)Lio/github/jichuo1/dexmeguviz/GraphResult;', 17), (b'startJob', b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;Lio/github/jichuo1/dexmeguviz/GraphQuery;IIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$GraphJob;', 17), (b'startJob', b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;Lio/github/jichuo1/dexmeguviz/GraphQuery;IIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$GraphJob;', 17)], 'UseGraphQueryExecution': [(b'execute', b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;[B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;', 17), (b'execute', b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;[B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;', 17)]})
    extra['ReflectionMethodUsesExecution']=[
      (b'execute',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;[B)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;',0x0011),
      (b'execute',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;[B)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;',0x0011),
      (b'startJob',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;[BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0011),
      (b'startJob',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;[BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0011)]
    text=b'L'+prefix+b'StaticTextMatch;';pred=b'L'+prefix+b'ReflectionMethodPredicate;';query=b'L'+prefix+b'ReflectionMethodUsesQuery;'
    extra['StaticTextMatch']=[(b'getOperation',b'()L'+prefix+b'TextOperation;',0x0011),(b'getValue',b'()Ljava/lang/String;',0x0011),(b'getAsciiCaseInsensitive',b'()Z',0x0011)]
    extra['InvokeTarget']=[(b'getOwner',b'()'+text,0x0011),(b'getName',b'()'+text,0x0011),(b'getPrototype',b'()'+text,0x0011),(b'getReturnType',b'()'+text,0x0011),(b'getMinParameters',b'()Ljava/lang/Long;',0x0011),(b'getMaxParameters',b'()Ljava/lang/Long;',0x0011),(b'getReferenceKind',b'()L'+prefix+b'InvokeReferenceKind;',0x0011),(b'<init>',b'()V',0x0001)]
    extra['FieldTarget']=[(b'getOwner',b'()'+text,0x0011),(b'getName',b'()'+text,0x0011),(b'getType',b'()'+text,0x0011),(b'getAccess',b'()L'+prefix+b'FieldUseAccess;',0x0011),(b'<init>',b'()V',0x0001)]
    extra['ReflectionMethodPredicate$Companion']=[
      (b'metadata',b'(L'+prefix+b'MethodPredicate;)'+pred,0x0011),
      (b'reflectionFlags',b'(L'+prefix+b'RawFlagOperation;L'+prefix+b'ReflectionFlags;)'+pred,0x0011),
      (b'reflectionOwnerFlags',b'(L'+prefix+b'RawFlagOperation;L'+prefix+b'ReflectionFlags;)'+pred,0x0011),
      (b'stringsAll',b'(['+text+b')'+pred,0x0091),(b'stringsAny',b'(['+text+b')'+pred,0x0091),
      (b'invokesAll',b'([L'+prefix+b'InvokeTarget;)'+pred,0x0091),(b'invokesAny',b'([L'+prefix+b'InvokeTarget;)'+pred,0x0091),
      (b'fieldsAll',b'([L'+prefix+b'FieldTarget;)'+pred,0x0091),(b'fieldsAny',b'([L'+prefix+b'FieldTarget;)'+pred,0x0091),
      (b'not',b'('+pred+b')'+pred,0x0011),(b'all',b'(['+pred+b')'+pred,0x0091),(b'any',b'(['+pred+b')'+pred,0x0091)]
    extra['ReflectionMethodUsesQuery']=[(b'<init>',b'('+pred+b'L'+prefix+b'QueryIntent;IJ)V',0x0001),(b'getWhere',b'()'+pred,0x0011),(b'getIntent',b'()L'+prefix+b'QueryIntent;',0x0011),(b'getMaxResults',b'()I',0x0011),(b'getMaxWork',b'()J',0x0011)]
    extra['TypedReflectionMethodUsesExecution']=[
      (b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;'+query+b')L'+prefix+b'NativeEngine$EntityResult;',0x0011),
      (b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;'+query+b')L'+prefix+b'NativeEngine$EntityResult;',0x0011),
      (b'startJob',b'(L'+prefix+b'NativeEngine$Snapshot;'+query+b'IIJ)L'+prefix+b'NativeEngine$EntityJob;',0x0011),
      (b'startJob',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;'+query+b'IIJ)L'+prefix+b'NativeEngine$EntityJob;',0x0011)]
    target_query=b'L'+prefix+b'UseTargetReferenceQuery;'
    extra['UseTargetReferenceQuery']=[(b'<init>',b'(L'+prefix+b'UseReferenceTarget;L'+prefix+b'UseEventPredicate;L'+prefix+b'EntityPredicate;L'+prefix+b'UseSymbolDirection;L'+prefix+b'UseSymbolJoin;L'+prefix+b'QueryIntent;IJ)V',0x0001)]
    extra['TypedUseTargetReferenceExecution']=[(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;'+target_query+b')L'+prefix+b'UseGraphResult;',0x0011),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;'+target_query+b')L'+prefix+b'UseGraphResult;',0x0011)]
    invoke_query=b'L'+prefix+b'InvokeSiteQuery;'
    extra['InvokeSiteQuery']=[(b'<init>',b'(L'+prefix+b'UseEventPredicate;L'+prefix+b'QueryIntent;IJ)V',0x0001)]
    extra['TypedInvokeSiteExecution']=[(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;'+invoke_query+b')L'+prefix+b'UseGraphResult;',0x0011),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;'+invoke_query+b')L'+prefix+b'UseGraphResult;',0x0011)]
    scoped_query=b'L'+prefix+b'ScopedInvokeSiteQuery;'
    extra['ScopedInvokeSiteQuery']=[(b'<init>',b'(Ljava/util/List;L'+prefix+b'UseEventPredicate;L'+prefix+b'QueryIntent;IJ)V',0x0001)]
    extra['ScopedUseGraphExecution']=[(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;[B)L'+prefix+b'UseGraphResult;',0x0011),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;[B)L'+prefix+b'UseGraphResult;',0x0011),(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;'+scoped_query+b')L'+prefix+b'UseGraphResult;',0x0011),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;'+scoped_query+b')L'+prefix+b'UseGraphResult;',0x0011)]
    extra['UseGraphQueryExecution'].extend([(b'startJob',b'(L'+prefix+b'NativeEngine$Snapshot;[BIIJ)L'+prefix+b'NativeEngine$UseGraphJob;',0x0011),(b'startJob',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;[BIIJ)L'+prefix+b'NativeEngine$UseGraphJob;',0x0011)])
    extra['ClassAnnotationGraphQuery']=[(b'<init>',b'(L'+prefix+b'GraphExpression;L'+prefix+b'QueryIntent;IJLjava/util/List;)V',1),(b'getRelation',b'()L'+prefix+b'GraphExpression;',17),(b'getIntent',b'()L'+prefix+b'QueryIntent;',17),(b'getMaxResults',b'()I',17),(b'getMaxWork',b'()J',17)]
    extra['ClassAnnotationGraphExecution']=[(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'ClassAnnotationGraphQuery;)L'+prefix+b'GraphResult;',17),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'ClassAnnotationGraphQuery;)L'+prefix+b'GraphResult;',17)]
    extra['TypeUseOpcode']=[(b'getCode',b'()I',17)]
    extra['TypeUsePredicate$Companion']=[(b'constant',b'(Z)L'+prefix+b'TypeUsePredicate;',17),(b'opcode',b'(L'+prefix+b'TypeUseOpcode;)L'+prefix+b'TypeUsePredicate;',17),(b'targetDescriptor',b'(L'+prefix+b'TextOperation;Ljava/lang/String;Z)L'+prefix+b'TypeUsePredicate;',17),(b'all',b'([L'+prefix+b'TypeUsePredicate;)L'+prefix+b'TypeUsePredicate;',145)]
    extra['TypeUseQuery']=[(b'<init>',b'(L'+prefix+b'TypeUsePredicate;L'+prefix+b'TypeUseJoinTarget;L'+prefix+b'EntityPredicate;L'+prefix+b'TypeUseJoinDirection;L'+prefix+b'TypeUseJoinKind;L'+prefix+b'QueryIntent;IJLjava/util/List;)V',1),(b'toQueryIrJson',b'()Ljava/lang/String;',17)]
    extra['TypeUseExecution']=[(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'TypeUseQuery;)L'+prefix+b'UseGraphResult;',17),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'TypeUseQuery;)L'+prefix+b'UseGraphResult;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'TypeUseQuery;IIJ)L'+prefix+b'NativeEngine$UseGraphJob;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'TypeUseQuery;IIJ)L'+prefix+b'NativeEngine$UseGraphJob;',17)]
    extra['AdvancedQuery']=[(b'<init>',b'(Ljava/lang/String;)V',1)]
    extra['AdvancedExecution']=[(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'AdvancedQuery;)L'+prefix+b'AdvancedResult;',17),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'AdvancedQuery;)L'+prefix+b'AdvancedResult;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'AdvancedQuery;IIJ)L'+prefix+b'NativeEngine$AdvancedJob;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'AdvancedQuery;IIJ)L'+prefix+b'NativeEngine$AdvancedJob;',17)]
    extra['InheritedUseGraphExecution']=[(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'AdvancedQuery;)L'+prefix+b'UseGraphResult;',17),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'AdvancedQuery;)L'+prefix+b'UseGraphResult;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'AdvancedQuery;IIJ)L'+prefix+b'NativeEngine$UseGraphJob;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'AdvancedQuery;IIJ)L'+prefix+b'NativeEngine$UseGraphJob;',17)]
    extra['InterfaceUseGraphExecution']=[(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'AdvancedQuery;)L'+prefix+b'UseGraphResult;',17),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'AdvancedQuery;)L'+prefix+b'UseGraphResult;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'AdvancedQuery;IIJ)L'+prefix+b'NativeEngine$UseGraphJob;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'AdvancedQuery;IIJ)L'+prefix+b'NativeEngine$UseGraphJob;',17)]
    extra['DexSourceExportExecution']=[(b'copy',b'(L'+prefix+b'NativeEngine$Snapshot;J)[B',17),(b'copy',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;IJ)[B',17)]
    extra['DexSourceExportExecution'] += [(name,b'(L'+prefix+b'NativeEngine$Snapshot;JI)Ljava/lang/String;',17) for name in (b'stringAt',b'typeAt',b'prototypeAt')] + [(name,b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;IJI)Ljava/lang/String;',17) for name in (b'stringAt',b'typeAt',b'prototypeAt')]
    extra['DexSourceExportExecution'] += [(name,b'(L'+prefix+b'NativeEngine$Snapshot;J)[J',17) for name in (b'fieldRefAt',b'methodRefAt')] + [(name,b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;IJ)[J',17) for name in (b'fieldRefAt',b'methodRefAt')]
    extra['AnnotationExecution']=[(b'inspect',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'Annotations$Target;L'+prefix+b'Annotations$Limits;)L'+prefix+b'AnnotationResult;',17),(b'inspect',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;IL'+prefix+b'Annotations$Target;L'+prefix+b'Annotations$Limits;)L'+prefix+b'AnnotationResult;',17)]
    extra['MethodFactsRequest']=[(b'<init>',b'(Ljava/util/Set;IJJ)V',1),(b'getCategories',b'()Ljava/util/Set;',17),(b'getMaxRecords',b'()I',17),(b'getMaxWork',b'()J',17),(b'getDeadlineAfterMs',b'()J',17)]
    extra['MethodFactsExecution']=[(b'inspect',b'(L'+prefix+b'NativeEngine$Snapshot;JL'+prefix+b'MethodFactsRequest;)L'+prefix+b'MethodFactsResult;',17),(b'inspect',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;IJL'+prefix+b'MethodFactsRequest;)L'+prefix+b'MethodFactsResult;',17)]
    extra['MethodParametersLimits']=[(b'<init>',b'(IIJJ)V',1),(b'getMaxParameters',b'()I',17),(b'getMaxTextUnits',b'()I',17),(b'getMaxWork',b'()J',17),(b'getDeadlineAfterMs',b'()J',17)]
    extra['MethodParametersExecution']=[(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;JL'+prefix+b'MethodParametersLimits;)L'+prefix+b'MethodParametersResult;',17),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;IJL'+prefix+b'MethodParametersLimits;)L'+prefix+b'MethodParametersResult;',17)]
    extra['MethodTypeTarget']=[(b'<init>',b'(L'+prefix+b'StaticTextMatch;L'+prefix+b'TypeUseOpcode;)V',1),(b'getOpcode',b'()L'+prefix+b'TypeUseOpcode;',17)]
    extra['MethodTypePredicate$Companion']=[(b'typesAll',b'([L'+prefix+b'MethodTypeTarget;)L'+prefix+b'MethodTypePredicate;',145),(b'stringsAll',b'([L'+prefix+b'StaticTextMatch;)L'+prefix+b'MethodTypePredicate;',145),(b'invokesAll',b'([L'+prefix+b'InvokeTarget;)L'+prefix+b'MethodTypePredicate;',145),(b'fieldsAll',b'([L'+prefix+b'FieldTarget;)L'+prefix+b'MethodTypePredicate;',145),(b'all',b'([L'+prefix+b'MethodTypePredicate;)L'+prefix+b'MethodTypePredicate;',145)]
    extra['MethodTypeQuery']=[(b'<init>',b'(L'+prefix+b'MethodTypePredicate;L'+prefix+b'QueryIntent;IJLjava/util/List;)V',1),(b'toQueryIrJson',b'()Ljava/lang/String;',17)]
    extra['MethodTypeExecution']=[(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'MethodTypeQuery;)L'+prefix+b'MethodTypeResult;',17),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'MethodTypeQuery;)L'+prefix+b'MethodTypeResult;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'MethodTypeQuery;IIJ)L'+prefix+b'NativeEngine$MethodTypeJob;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'MethodTypeQuery;IIJ)L'+prefix+b'NativeEngine$MethodTypeJob;',17)]
    extra['ExpandExecution']=[(b'execute',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'ExpandQuery;)L'+prefix+b'ExpandResult;',17),(b'execute',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'ExpandQuery;)L'+prefix+b'ExpandResult;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$Snapshot;L'+prefix+b'ExpandQuery;IIJ)L'+prefix+b'NativeEngine$ExpandJob;',17),(b'startJob',b'(L'+prefix+b'NativeEngine$SourceSetSnapshot;L'+prefix+b'ExpandQuery;IIJ)L'+prefix+b'NativeEngine$ExpandJob;',17)]
    extra['ExpandExecution'] += [(name, signature.replace(b'ExpandQuery;',b'ExpandGraphQuery;'), flags) for name,signature,flags in extra['ExpandExecution']]
    for target in extra.get(name,[]):
        method=[m for m in clazz['methods'] if (m['name'],m['descriptor'])==target[:2]]
        if len(method)!=1 or method[0]['access']!=target[2] or sum(a[0]==b'Code' for a in method[0]['attributes'])!=1:
            raise ValueError('Kotlin bridge method mismatch: '+name+' '+target[0].decode('ascii')+' '+target[1].decode('ascii'))

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--aar',type=Path,required=True)
    p.add_argument('--header',type=Path,required=True)
    p.add_argument('--readelf',type=Path,required=True)
    p.add_argument('--runtime-report',type=Path,required=True)
    p.add_argument('--expect-kotlin',action='store_true')
    p.add_argument('--pom',type=Path)
    p.add_argument('--module',type=Path)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    data=file_bytes(a.aar,AAR_BYTES);sha=lambda b:hashlib.sha256(b).hexdigest()
    header_data=file_bytes(a.header,HEADER_BYTES);header=header_data.decode('utf-8')
    api_headers=[{'name':a.header.name,'sha256':sha(header_data)}]
    # This independently versioned default-core API is present only in newer
    # source snapshots. Optional Android persistent-cache headers are not read.
    parameters_header=a.header.with_name('method_parameters_v1.h')
    if parameters_header.exists():
        extra=file_bytes(parameters_header,HEADER_BYTES);header+='\n'+extra.decode('utf-8')
        api_headers.append({'name':parameters_header.name,'sha256':sha(extra)})
    fast_header=a.header.with_name('fast_query_v1.h')
    if fast_header.exists():
        extra=file_bytes(fast_header,HEADER_BYTES);header+='\n'+extra.decode('utf-8')
        api_headers.append({'name':fast_header.name,'sha256':sha(extra)})
    expected=set(re.findall(r'\b(?:dmg_status|void|uint32_t|const\s+char\s*\*)\s*(dmg_[A-Za-z0-9_]+)\s*\(',header))
    if not expected:raise SystemExit('no C API declarations found')
    jni={'Java_io_github_jichuo1_dexmeguviz_FastDexQuery_nativeCompile','Java_io_github_jichuo1_dexmeguviz_FastDexQuery_nativeScan','Java_io_github_jichuo1_dexmeguviz_FastDexQuery_nativeClose','Java_io_github_jichuo1_dexmeguviz_FastDexQuery_nativeScanArchives',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_abiVersion','Java_io_github_jichuo1_dexmeguviz_NativeEngine_capabilities',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenRawDex',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenRawDexWithLimits',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeCreateMethodStream',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenMethodStreamDex',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeMethodStreamQuery',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeMethodStreamQueryBatch',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeCloseMethodStream',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeSnapshotInfo',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeClose',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryMethods',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenRawDexSet',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenSources',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenApkFdSources',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenApkPaths',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeSourceSetInfo',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQuerySourceSetMethods',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartMethodJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartOpcodeJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeJobNext',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeJobStatus',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeJobCancel',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeJobClose',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryEntities',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryReflectionMethodUses',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartReflectionMethodUsesJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartEntityJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartClassAnnotationJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartClassAnnotationStringJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeEntityJobNext',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryExpand',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartExpandJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeExpandJobNext',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeExpandJobStatus',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeInspectMethodCalls',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeInspectMethodFacts',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeInspectMethodParameters',
         'Java_io_github_jichuo1_dexmeguviz_ScopedMethodQuery_nativeExecute',
         'Java_io_github_jichuo1_dexmeguviz_ScopedMethodQuery_nativeStart',
         'Java_io_github_jichuo1_dexmeguviz_Annotations_nativeCollect',
         'Java_io_github_jichuo1_dexmeguviz_DexSourceExport_nativeBytes',
         'Java_io_github_jichuo1_dexmeguviz_DexSourceExport_nativeSymbol',
         'Java_io_github_jichuo1_dexmeguviz_DexSourceExport_nativeMemberIndices',
         'Java_io_github_jichuo1_dexmeguviz_DexStreamExport_nativeRead',
         'Java_io_github_jichuo1_dexmeguviz_OpcodeQuery_nativeExecute',
         'Java_io_github_jichuo1_dexmeguviz_MethodBatchQuery_nativeExecute',
         'Java_io_github_jichuo1_dexmeguviz_ScopedMethodBatchQuery_nativeExecute',
         'Java_io_github_jichuo1_dexmeguviz_ClassAnnotationQuery_nativeExecute',
         'Java_io_github_jichuo1_dexmeguviz_ScopedClassAnnotationQuery_nativeExecute',
         'Java_io_github_jichuo1_dexmeguviz_ScopedClassAnnotationQuery_nativeStart',
         'Java_io_github_jichuo1_dexmeguviz_ClassAnnotationStringQuery_nativeExecute',
         'Java_io_github_jichuo1_dexmeguviz_ScopedClassAnnotationStringQuery_nativeExecute',
         'Java_io_github_jichuo1_dexmeguviz_ScopedClassAnnotationStringQuery_nativeStart',
         'Java_io_github_jichuo1_dexmeguviz_ScopedOpcodeQuery_nativeExecute',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryAdvanced',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartAdvancedJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeAdvancedJobNext',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryMethodType',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartMethodTypeJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeMethodTypeJobNext',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryTypeUseGraph',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryInheritedUseGraph',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryInterfaceUseGraph',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartInterfaceUseGraphJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartInheritedUseGraphJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartTypeUseGraphJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryClassAnnotationGraph',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryGraph',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryUseGraph',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryUseGraphScopedV4',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryFieldDeclarationGraph',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryCallerFieldRelationGraph',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartGraphJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeGraphJobNext',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartUseGraphJob',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeUseGraphJobNext',
         'Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeUseGraphJobStatus'}
    deps=file_bytes(a.runtime_report,REPORT_BYTES).decode('utf-8',errors='replace')
    check_runtime_report(deps)
    if (a.pom is None)!=(a.module is None) or (a.expect_kotlin and a.pom is None):
        raise ValueError('Kotlin audit requires both POM and module metadata')
    publication=check_publication(file_bytes(a.pom,POM_BYTES),file_bytes(a.module,MODULE_BYTES),data) if a.pom else None
    result={'aar_sha256':sha(data),'aar_bytes':len(data),'runtime_classpath':'No dependencies','api_headers':api_headers,'public_c_export_count':len(expected),'abis':{},'scope':'static fixed-profile checks; ZIP metadata checked for all entries, payloads only for selected members; no complete ZIP/class/ELF verifier, Android load or runtime claim'}
    if publication:result['publication']=publication
    with ZipFile(io.BytesIO(data)) as z:
        check_archive(z,AAR_ENTRIES,AAR_TOTAL_UNCOMPRESSED,AAR_MEMBER,'AAR')
        wanted={'jni/arm64-v8a/libdexmeguviz.so','jni/armeabi-v7a/libdexmeguviz.so'}
        if {n for n in z.namelist() if n.endswith('.so')}!=wanted:raise SystemExit('unexpected shared libraries')
        if any(n.lower().endswith('.jar') and n!='classes.jar' for n in z.namelist()):raise SystemExit('unexpected embedded jar')
        if any(n.startswith('kotlin/') for n in z.namelist()):raise SystemExit('embedded Kotlin runtime path')
        manifest=ET.fromstring(member_bytes(z,'AndroidManifest.xml',TEXT_MEMBER));sdk=manifest.find('uses-sdk')
        if sdk is None or sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion')!='27':raise SystemExit('wrong minSdk')
        try:verify_keep(member_bytes(z,'proguard.txt',TEXT_MEMBER).decode('utf-8'))
        except (UnicodeError,ClassError) as e:raise SystemExit('JNI keep rule invalid: '+str(e))
        with ZipFile(io.BytesIO(member_bytes(z,'classes.jar',JAR_BYTES))) as classes:
            check_archive(classes,JAR_ENTRIES,JAR_TOTAL_UNCOMPRESSED,JAR_MEMBER,'classes.jar')
            names=[x for x in classes.namelist() if x.endswith('.class')]
            prefix='io/github/jichuo1/dexmeguviz/'
            expected_classes={'io/github/jichuo1/dexmeguviz/NativeEngine.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$Snapshot.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$SnapshotInfo.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$NativeFailure.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$MethodCandidate.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$QueryResult.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$SourceSetInfo.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$RawDexSourceInfo.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$InputInfo.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$Job.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$JobPoll.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$JobStatus.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$EntityCandidate.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$EntityResult.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$EntityJob.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$EntityJobPoll.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$EntityJobStatus.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$GraphJob.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$GraphJobPoll.class',
                              'io/github/jichuo1/dexmeguviz/NativeEngine$GraphJobStatus.class',
                              'io/github/jichuo1/dexmeguviz/GraphResult.class',
                              'io/github/jichuo1/dexmeguviz/GraphResult$Binding.class',
                              'io/github/jichuo1/dexmeguviz/GraphResult$Entity.class',
                              'io/github/jichuo1/dexmeguviz/GraphResult$Input.class',
                              'io/github/jichuo1/dexmeguviz/GraphResult$Link.class',
                              'io/github/jichuo1/dexmeguviz/GraphResult$Operator.class',
                              'io/github/jichuo1/dexmeguviz/GraphResult$Profile.class',
                              'io/github/jichuo1/dexmeguviz/GraphResult$Reader.class',
                              'io/github/jichuo1/dexmeguviz/GraphResult$Row.class',
                              'io/github/jichuo1/dexmeguviz/GraphResult$Source.class',
                              'io/github/jichuo1/dexmeguviz/GraphResult$Witness.class'}
            expected_classes.update(prefix+n+'.class' for n in ['UseGraphResult', 'UseGraphResult$Binding', 'UseGraphResult$Entity', 'UseGraphResult$Identity', 'UseGraphResult$Input', 'UseGraphResult$Link', 'UseGraphResult$Operator', 'UseGraphResult$Profile', 'UseGraphResult$Reader', 'UseGraphResult$Row', 'UseGraphResult$Source', 'UseGraphResult$Use', 'UseGraphResult$Value', 'UseGraphResult$Witness'])
            expected_classes.update(prefix+n+'.class' for n in ['NativeEngine$UseGraphJob','NativeEngine$UseGraphJobPoll','NativeEngine$UseGraphJobStatus'])
            expected_classes.add(prefix+'GraphResult$ClassAnnotationFlags.class')
            expected_classes.update(prefix+n+'.class' for n in ['NativeEngine$ExpandJob', 'NativeEngine$ExpandJobPoll', 'ExpandResult', 'ExpandResult$Reader', 'ExpandResult$Profile', 'ExpandResult$Operator', 'ExpandResult$Input', 'ExpandResult$Source', 'ExpandResult$Entity', 'ExpandResult$Use', 'ExpandResult$Value', 'ExpandResult$Identity', 'ExpandResult$Binding', 'ExpandResult$Link', 'ExpandResult$ExpandProfile', 'ExpandResult$Witness', 'ExpandResult$Hop', 'ExpandResult$Evidence', 'ExpandResult$Path', 'ExpandResult$Row', 'ExpandResult$RowEvidence', 'ExpandResult$Frontier'])
            expected_classes.update(prefix+n+'.class' for n in ['NativeEngine$MethodTypeJob','NativeEngine$MethodTypeJobPoll','MethodTypeResult','MethodTypeResult$Reader','MethodTypeResult$Row','MethodTypeResult$Witness'])
            expected_classes.update(prefix+n+'.class' for n in ADVANCED_CLASSES+METHOD_CALLS_CLASSES+METHOD_FACTS_CLASSES+METHOD_PARAMETERS_CLASSES+SCOPED_METHOD_CLASSES+ANNOTATION_CLASSES+SOURCE_EXPORT_CLASSES+OPCODE_CLASSES+SCOPED_OPCODE_CLASSES+CLASS_ANNOTATION_QUERY_CLASSES+SCOPED_CLASS_ANNOTATION_CLASSES+CLASS_ANNOTATION_STRING_CLASSES+METHOD_BATCH_CLASSES+SCOPED_METHOD_BATCH_CLASSES+['MethodFactsResult$Category','MethodFactsResult$Availability'])
            expected_classes.add(prefix+'NativeEngine$MethodStream.class')
            jni_classes=set(expected_classes)
            annotation_matcher_classes={prefix+n+'.class' for n in ['AnnotationMatcher','AnnotationMatcher$Resolver','BoundAnnotationText','AnnotationArrayMatcher']}
            expected_classes.update(annotation_matcher_classes)
            encoded_value_classes={prefix+n+'.class' for n in ENCODED_VALUE_CLASSES}
            expected_classes.update(encoded_value_classes)
            precompute_classes={prefix+'precompute/'+n+'.class' for n in PRECOMPUTE_CLASSES}
            expected_classes.update(precompute_classes)
            binder_classes={prefix+n+'.class' for n in ['RuntimeMethodBinder','RuntimeMethodBinder$Origin','RuntimeMethodBinder$InvocationKind','RuntimeMethodBinder$Result','RuntimeMethodBinder$Signature','RuntimeMethodBinder$Status']}
            expected_classes.update(binder_classes)
            member_binder_classes={prefix+n+'.class' for n in ['RuntimeMemberBinder','RuntimeMemberBinder$Context','RuntimeMemberBinder$Kind','RuntimeMemberBinder$Result','RuntimeMemberBinder$Status']}
            expected_classes.update(member_binder_classes)
            apk_fd_classes={prefix+n+'.class' for n in ['ApkFdLimits','ApkFdInputs','ApkMetadataPlan','ApkMetadataPlan$Entry','ApkMetadataPlan$LoaderDeclaration','AndroidApkSources','AndroidApkSources$Opened','AndroidApkSources$PathOpener','AndroidApkSources$FdOpener']}
            expected_classes.update(apk_fd_classes)
            observation_classes={prefix+n+'.class' for n in ['MethodSourceObservation','MethodSourceObservation$Result','MethodSourceObservation$Observation']}
            expected_classes.update(observation_classes)
            trusted_apk_source_classes={prefix+n+'.class' for n in TRUSTED_APK_SOURCE_CLASSES}
            expected_classes.update(trusted_apk_source_classes)
            parallel_dex_query_classes={prefix+n+'.class' for n in PARALLEL_DEX_QUERY_CLASSES}
            expected_classes.update(parallel_dex_query_classes)
            parallel_fast_query_classes={prefix+n+'.class' for n in PARALLEL_FAST_QUERY_CLASSES}
            expected_classes.update(parallel_fast_query_classes)
            native_apk_fast_classes={prefix+n+'.class' for n in NATIVE_APK_FAST_CLASSES}
            expected_classes.update(native_apk_fast_classes)
            fast_query_classes={prefix+n+'.class' for n in ['FastDexQuery','FastDexQuery$Failure','FastDexQuery$Limits','FastDexQuery$InputAssumption','FastDexQuery$Plans','FastDexQuery$Call','FastDexQuery$Method','FastDexQuery$DexClass','FastDexQuery$RuleResult','FastDexQuery$Result']}
            expected_classes.update(fast_query_classes)
            caller_relation_classes={prefix+n+'.class' for n in ['CallerFieldRelationResult','CallerFieldRelationResult$Status','CallerFieldRelationResult$Relation','CallerFieldRelationResult$Node','CallerFieldRelationResult$Edge','CallerFieldRelationResult$InterfaceObjectCheck']}
            expected_classes.update(caller_relation_classes)
            kotlin={'GraphQueryExecution','Coverage','Decision','DecisionReason','ExecutionStatus','MethodPredicate$Companion','MethodPredicate','MethodQuery','MethodTextField','QueryExecution','QueryIntent','QuerySummary','RawDexFlags','RawFlagOperation','SourceIdentity','TextOperation','EntityPredicate$Companion','EntityPredicate','EntityQuery','EntityRelation','EntityTextField'}
            kotlin.update(['GraphExpression', 'GraphExpression$Companion', 'GraphExpression$Companion$WhenMappings', 'GraphIdentity', 'GraphJoinKey', 'GraphPredicate', 'GraphPredicate$Companion', 'GraphQuery', 'GraphRolePolicy', 'GraphSetSemantics', 'ReflectionFlags', 'TypedGraphQueryExecution', 'UseGraphQueryExecution', 'ReflectionMethodUsesExecution'])
            kotlin.update(['StaticTextMatch','InvokeReferenceKind','FieldUseAccess','InvokeTarget','FieldTarget','ReflectionMethodPredicate','ReflectionMethodPredicate$Companion','ReflectionMethodUsesQuery','ReflectionMethodUsesQueryKt','TypedReflectionMethodUsesExecution'])
            kotlin.update(['UseSymbolTarget','UseSymbolDirection','UseSymbolJoin','UseEventTextField','UseEventNumberField','UseEventTargetDomain','UseEventPredicate','UseEventPredicate$Companion','UseTargetSymbolQuery','TypedUseTargetSymbolExecution'])
            kotlin.update(['UseReferenceTarget','UseTargetReferenceQuery','TypedUseTargetReferenceExecution'])
            kotlin.update(['InvokeSiteQuery','TypedInvokeSiteExecution'])
            kotlin.update(['ScopedInvokeSiteQuery','ScopedUseGraphExecution'])
            kotlin.update(['FieldDeclarationScope','FieldDeclarationQuery','FieldDeclarationQuery$WhenMappings','FieldDeclarationQueryExecution'])
            kotlin.update(['FieldDeclarationCallerQuery','TypedFieldDeclarationCallerExecution'])
            kotlin.update(['CallerFieldRelationQuery','CallerFieldRelationExecution'])
            kotlin.update(['ClassAnnotationGraphQuery','ClassAnnotationGraphExecution'])
            kotlin.update(['TypeUseOpcode','TypeUseJoinTarget','TypeUseJoinDirection','TypeUseJoinKind','TypeUsePredicate','TypeUsePredicate$Companion','TypeUseQuery','TypeUseExecution'])
            kotlin.update(['ExpandDirection','ExpandOutput','ExpandQuery','ExpandGraphQuery','ExpandExecution'])
            kotlin.update(['MethodTypeTarget','MethodTypePredicate','MethodTypePredicate$Companion','MethodTypeQuery','MethodTypeExecution','MethodTypeQueryKt'])
            kotlin.update({'AdvancedQuery','AdvancedExecution','InheritedUseGraphExecution','InterfaceUseGraphExecution'})
            kotlin.update({'MethodFactsRequest','MethodFactsExecution','MethodParametersLimits','MethodParametersExecution'})
            kotlin.update({'AnnotationExecution','DexSourceExportExecution'})
            if a.expect_kotlin:expected_classes.update(prefix+n+'.class' for n in kotlin)
            if any(n.startswith('kotlin/') or n.lower().endswith('.jar') for n in classes.namelist()):raise SystemExit('embedded Kotlin runtime or nested jar')
            if set(names)!=expected_classes or len(names)!=len(expected_classes):raise SystemExit('unexpected class files; extra='+repr(sorted(set(names)-expected_classes))+' missing='+repr(sorted(expected_classes-set(names))))
            code=member_bytes(classes,'io/github/jichuo1/dexmeguviz/NativeEngine.class',JAR_MEMBER)
            if b'kotlin/' in code or b'abiVersion' not in code or b'capabilities' not in code:raise SystemExit('unexpected Java class contents')
            for name in names:
                code=member_bytes(classes,name,JAR_MEMBER)
                if name in jni_classes and b'kotlin/' in code:raise SystemExit('unexpected Kotlin reference in JNI class')
                try:parsed=parse(code)
                except ClassError as e:raise SystemExit('invalid class structure: '+str(e))
                if parsed['name']!=name[:-6].encode('utf-8'):raise SystemExit('class path and class identity differ: '+name)
                if name in annotation_matcher_classes:check_annotation_matcher_class(parsed,name[len(prefix):-6])
                elif name in encoded_value_classes:check_encoded_value_class(parsed,name[len(prefix):-6])
                elif name in precompute_classes:check_precompute_class(parsed,name[len(prefix):-6])
                elif name in binder_classes:check_binder_class(parsed,name[len(prefix):-6])
                elif name in member_binder_classes:check_member_binder_class(parsed,name[len(prefix):-6])
                elif name in apk_fd_classes:check_apk_fd_class(parsed,name[len(prefix):-6])
                elif name in observation_classes:check_method_observation_class(parsed,name[len(prefix):-6])
                elif name in trusted_apk_source_classes:check_trusted_apk_source_class(parsed,name[len(prefix):-6])
                elif name in parallel_dex_query_classes:check_parallel_dex_query_class(parsed,name[len(prefix):-6])
                elif name in parallel_fast_query_classes:check_parallel_fast_query_class(parsed,name[len(prefix):-6])
                elif name in native_apk_fast_classes:check_native_apk_fast_class(parsed,name[len(prefix):-6])
                elif name in fast_query_classes:
                    natives={(m['name'],m['descriptor'],m['access']) for m in parsed['methods'] if m['access']&0x0100}
                    want={(b'nativeCompile',b'([[B[Z)J',0x010a),(b'nativeScan',b'(J[BJIIJIII)[B',0x010a),(b'nativeClose',b'(J)V',0x010a),(b'nativeScanArchives',b'(J[Ljava/lang/String;[Ljava/lang/String;[Z[J[JZI)[B',0x010a)} if name==prefix+'FastDexQuery.class' else set()
                    if natives!=want:raise SystemExit('unexpected FastDexQuery JNI ABI: '+name)
                elif name in caller_relation_classes:check_caller_relation_class(parsed,name[len(prefix):-6])
                elif name not in jni_classes:check_kotlin_class(parsed,name[len(prefix):-6])
            try:verify_classfiles({name:member_bytes(classes,name,JAR_MEMBER) for name in names})
            except (ClassError,KeyError) as e:raise SystemExit('invalid JNI class ABI: '+str(e))
            result['java_class_major']=61
            result['java_class_minor']=0
            result['classes']=sorted(names)
        result['aar_entries']=z.namelist();result['aar_metadata']=member_bytes(z,'META-INF/com/android/build/gradle/aar-metadata.properties',TEXT_MEMBER).decode('utf-8')
        for abi,machine in [('arm64-v8a','AArch64'),('armeabi-v7a','ARM')]:
            member='jni/'+abi+'/libdexmeguviz.so';blob=member_bytes(z,member,AAR_MEMBER);directory=a.out/abi;directory.mkdir();local=directory/'libdexmeguviz.so';local.write_bytes(blob)
            command=[str(a.readelf),'--wide','--file-header','--program-headers','--dynamic-table','--dyn-syms',str(local)]
            proc=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
            (directory/'readelf.stdout.log').write_text(proc.stdout,encoding='utf-8');(directory/'readelf.stderr.log').write_text(proc.stderr,encoding='utf-8')
            if proc.returncode:raise SystemExit('readelf failure: '+abi)
            check_elf_header(proc.stdout,abi)
            soname=re.findall(r'\(SONAME\).*\[(.*?)\]',proc.stdout);needed=sorted(re.findall(r'\(NEEDED\).*\[(.*?)\]',proc.stdout))
            if soname!=['libdexmeguviz.so'] or needed!=['libc.so','libdl.so','libm.so']:raise SystemExit('unexpected native dependencies: '+abi)
            loads=[]
            for line in proc.stdout.splitlines():
                parts=line.split()
                if parts and parts[0]=='LOAD':
                    offset,vaddr,align=int(parts[1],16),int(parts[2],16),int(parts[-1],16)
                    if align<16384 or offset%align!=vaddr%align:raise SystemExit('invalid load alignment: '+abi)
                    loads.append({'offset':offset,'vaddr':vaddr,'alignment':align})
            exports,undefined=check_elf_symbols(proc.stdout,expected|jni,abi)
            if not loads:raise SystemExit('missing load segments: '+abi)
            result['abis'][abi]={'bytes':len(blob),'sha256':sha(blob),'machine':machine,'soname':soname[0],'needed':needed,'load_segments':loads,'exports':sorted(exports),'undefined':sorted(set(undefined)),'aar_compression':z.getinfo(member).compress_type}
    (a.out/'audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'aar_sha256':result['aar_sha256'],'runtime_classpath':result['runtime_classpath'],'exports_per_abi':len(expected)+len(jni),'scope':result['scope']}))
if __name__=='__main__':
    try:main()
    except MemoryError:
        raise SystemExit('AAR audit memory exhausted')
    except (BadZipFile,EOFError,KeyError,OSError,RuntimeError,ValueError,ET.ParseError,subprocess.TimeoutExpired,zlib.error) as e:
        raise SystemExit('invalid or unsupported AAR input: '+str(e))

