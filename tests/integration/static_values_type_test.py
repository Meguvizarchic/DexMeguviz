"""Original, reproducible DEX static-value semantic fixtures.

Produces project-original fixtures in a fresh output directory. Outcomes cover
metadata parsing only; no ART loading, runtime class initialization or full DEX
verifier is claimed. The generator deliberately does not import production code.
"""
from pathlib import Path
import argparse, hashlib, json, struct, subprocess, time, zlib

OBJ = 'Ljava/lang/Object;'
FIELD_NAME = 'value'
TYPES = {'Z': b'\x1f', 'B': b'\x00\x00', 'S': b'\x02\x00', 'C': b'\x03\x00',
         'I': b'\x04\x00', 'J': b'\x06\x00', 'F': b'\x10\x00', 'D': b'\x11\x00'}


def leb(n):
    out = bytearray()
    while True:
        low = n & 0x7f
        n >>= 7
        out.append(low | (0x80 if n else 0))
        if not n:
            return bytes(out)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def expected_diagnostic(name, status):
    if status == 'Complete': return None
    if status == 'BudgetExceeded': return 'expanded metadata lists exceed 1000000 entries'
    if name.startswith(('wrong-primitive-', 'shared-invalid-')) or name in (
        'two-static-swapped', 'two-static-second-wrong', 'shared-two-static-invalid-second'):
        return 'static field value type does not match field type'
    if name.startswith(('primitive-null-', 'primitive-string-', 'primitive-type-')):
        return 'static reference value requires a reference field'
    if name in ('two-values-one-static', 'nonempty-values-no-classdata', 'three-values-two-static'):
        return 'static values exceed static field count'
    if name in ('nested-array-as-static', 'field-ref-as-static', 'enum-ref-as-static'):
        return 'unsupported static field value kind'
    raise ValueError('no expected diagnostic for negative case: ' + name)


def build(classes, extra_arrays=()):
    """classes: [(field_descriptor, static_field_exists, array_or_none), ...]."""
    owners = ['Lfixture/C%02d;' % i for i in range(len(classes))]
    field_descriptors = [((t,) if isinstance(t,str) else tuple(t)) if exists else () for t,exists,_ in classes]
    descriptors = {OBJ, 'V', 'I', '[I', *owners, *(d for values in field_descriptors for d in values),
                   *(t for t,_,_ in classes if isinstance(t,str))}
    field_names = {FIELD_NAME} | {'value%02d' % j for values in field_descriptors if len(values)>1 for j in range(len(values))}
    strings = sorted(descriptors | field_names)
    sid = {s:i for i,s in enumerate(strings)}
    types = sorted(descriptors, key=sid.__getitem__)
    tid = {s:i for i,s in enumerate(types)}
    fields = sorted([(owners[i], t, FIELD_NAME if len(values)==1 else 'value%02d' % j)
                     for i,values in enumerate(field_descriptors) for j,t in enumerate(values)],
                    key=lambda f:(tid[f[0]],sid[f[2]],tid[f[1]]))
    field_ids = {owner:[i for i,(field_owner,_,_) in enumerate(fields) if field_owner==owner] for owner in owners}
    data = bytearray(112)
    sections = [(0,1,0)]

    def table(kind,count,width):
        if not count: return 0
        offset=len(data);data.extend(bytes(count*width));sections.append((kind,count,offset));return offset
    strings_at=table(1,len(strings),4);types_at=table(2,len(types),4)
    fields_at=table(4,len(fields),8);classes_at=table(6,len(classes),32)
    data_at=len(data)
    sections.append((0x2002,len(strings),len(data)))
    for i,s in enumerate(strings):
        struct.pack_into('<I',data,strings_at+i*4,len(data))
        encoded=s.encode('ascii');data.extend(leb(len(s))+encoded+b'\0')
    class_data={}
    if fields:
        sections.append((0x2000,sum(bool(v) for v in field_descriptors),len(data)))
        for i,ids in enumerate(field_ids.values()):
            if ids:
                class_data[i]=len(data)
                data.extend(leb(len(ids))+b'\x00\x00\x00')
                previous=0
                for field_id in ids:
                    data.extend(leb(field_id-previous)+b'\x09')
                    previous=field_id
    arrays=[]
    for _,_,a in classes:
        if a is not None and a not in arrays: arrays.append(a)
    for a in extra_arrays:
        if a not in arrays: arrays.append(a)
    array_offsets={}
    if arrays:
        sections.append((0x2005,len(arrays),len(data)))
        for a in arrays:
            array_offsets[a]=len(data);data.extend(a)
    data.extend(bytes(-len(data)%4))
    map_at=len(data);sections.append((0x1000,1,map_at));data.extend(struct.pack('<I',len(sections)))
    for kind,count,offset in sorted(sections,key=lambda x:x[2]): data.extend(struct.pack('<HHII',kind,0,count,offset))
    for i,t in enumerate(types):struct.pack_into('<I',data,types_at+i*4,sid[t])
    for i,(owner,t,name) in enumerate(fields):struct.pack_into('<HHI',data,fields_at+i*8,tid[owner],tid[t],sid[name])
    for i,(t,exists,a) in enumerate(classes):
        struct.pack_into('<8I',data,classes_at+i*32,tid[owners[i]],1,tid[OBJ],0,0xffffffff,0,
                         class_data.get(i,0),array_offsets.get(a,0))
    data[:8]=b'dex\n038\0'
    struct.pack_into('<20I',data,32,len(data),112,0x12345678,0,0,map_at,len(strings),strings_at,
                     len(types),types_at,0,0,len(fields),fields_at,0,0,len(classes),classes_at,len(data)-data_at,data_at)
    data[12:32]=hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff)
    identity={'classes':len(classes),'array_offsets':[array_offsets.get(c[2],0) for c in classes],
              'class_data_offsets':[class_data.get(i,0) for i in range(len(classes))],
              'field_types':[c[0] for c in classes],'static_fields':[c[1] for c in classes],
              'encoded_arrays':[a.hex() for a in arrays],'type_ids':tid,'string_ids':sid}
    return data,identity


def run():
    p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--output',type=Path);p.add_argument('--root',type=Path)
    args=p.parse_args()
    if args.output is None:
        if args.root is None: p.error('one of --output or --root is required')
        args.output=args.root/'docs/evidence/static-values'/('run-'+str(time.time_ns()))
    args.output.mkdir(parents=True,exist_ok=False)
    cases=[]
    def add(name,status,classes,extra=()): cases.append((name,status,classes,extra))
    for desc,value in TYPES.items():
        add('primitive-'+desc,'Complete',[(desc,True,b'\x01'+value)])
        other=TYPES['I'] if desc=='J' else TYPES['J']
        add('wrong-primitive-'+desc,'CorruptInput',[(desc,True,b'\x01'+other)])
    for ref in [OBJ,'[I']:
        label='object' if ref==OBJ else 'array'
        for name,value in [('null',b'\x1e'),('string',b'\x17\x00'),('type',b'\x18\x00')]:
            add(label+'-'+name,'Complete',[(ref,True,b'\x01'+value)])
            add('primitive-'+name+'-'+label,'CorruptInput',[('J',True,b'\x01'+value)])
    add('empty-value-one-static','Complete',[('J',True,b'\x00')])
    add('absent-values-one-static','Complete',[('J',True,None)])
    add('two-values-one-static','CorruptInput',[('J',True,b'\x02\x06\x00\x06\x00')])
    add('nonempty-values-no-classdata','CorruptInput',[('J',False,b'\x01\x06\x00')])
    add('empty-values-no-classdata','Complete',[('J',False,b'\x00')])
    add('nested-array-as-static','CorruptInput',[(OBJ,True,b'\x01\x1c\x00')])
    add('field-ref-as-static','CorruptInput',[(OBJ,True,b'\x01\x19\x00')])
    add('enum-ref-as-static','CorruptInput',[(OBJ,True,b'\x01\x1b\x00')])
    add('two-classes-share-long','Complete',[('J',True,b'\x01\x06\x00'),('J',True,b'\x01\x06\x00')])
    add('shared-invalid-second','CorruptInput',[('J',True,b'\x01\x06\x00'),('I',True,b'\x01\x06\x00')])
    add('shared-invalid-first','CorruptInput',[('I',True,b'\x01\x06\x00'),('J',True,b'\x01\x06\x00')])
    add('shared-empty-zero-and-one-static','Complete',[('J',False,b'\x00'),('J',True,b'\x00')])
    add('two-static-empty','Complete',[(('I','J'),True,b'\x00')])
    add('two-static-prefix','Complete',[(('I','J'),True,b'\x01\x04\x00')])
    add('two-static-both-valid','Complete',[(('I','J'),True,b'\x02\x04\x00\x06\x00')])
    add('two-static-swapped','CorruptInput',[(('I','J'),True,b'\x02\x06\x00\x04\x00')])
    add('two-static-second-wrong','CorruptInput',[(('I','J'),True,b'\x02\x04\x00\x04\x00')])
    add('three-values-two-static','CorruptInput',[(('I','J'),True,b'\x03\x04\x00\x06\x00\x06\x00')])
    add('shared-two-static','Complete',[(('I','J'),True,b'\x02\x04\x00\x06\x00'),(('I','J'),True,b'\x02\x04\x00\x06\x00')])
    add('shared-two-static-invalid-second','CorruptInput',[(('I','J'),True,b'\x02\x04\x00\x06\x00'),(('I','I'),True,b'\x02\x04\x00\x06\x00')])
    # A huge encoded array count trips the reader's documented aggregate item
    # budget before payload bytes are needed; this is not a DEX format limit.
    add('encoded-array-item-budget','BudgetExceeded',[('J',True,leb(1000001))])
    add('unreferenced-array-item-budget','BudgetExceeded',[('J',True,None)],(leb(1000001),))
    before=sha(args.exe.read_bytes()); records=[]
    for name,expected,classes,extra in cases:
        image,identity=build(classes,extra)
        assert image[12:32]==hashlib.sha1(image[32:]).digest()
        assert struct.unpack_from('<I',image,8)[0]==zlib.adler32(image[12:])&0xffffffff
        if name.startswith('shared-') or name=='two-classes-share-long':
            assert identity['array_offsets'][0]==identity['array_offsets'][1]!=0
        path=args.output/(name+'.dex');path.write_bytes(image)
        r=subprocess.run([str(args.exe),'inspect',str(path),'--json'],capture_output=True,timeout=60)
        out=r.stdout.decode('utf-8','replace');err=r.stderr.decode('utf-8','replace')
        try: actual=json.loads(out)['execution_status']
        except (ValueError,KeyError,TypeError):actual=err.split(':',1)[0]
        code={'Complete':0,'CorruptInput':2,'BudgetExceeded':3}[expected]
        diagnostic=expected_diagnostic(name,expected)
        good=actual==expected and r.returncode==code and (diagnostic is None or diagnostic in err)
        records.append({'name':name,'expected_status':expected,'actual_status':actual,'expected_exit':code,
                        'actual_exit':r.returncode,'expected_diagnostic':diagnostic,'sha256':sha(image),
                        'identity':identity,'valid':good,'stderr':err[:700]})
    after=sha(args.exe.read_bytes());failed=[x['name'] for x in records if not x['valid']]
    if before!=after:failed.append('executable-changed')
    summary={'scope':'project-original structural samples, AOSP primitive/reference categories; no ART or runtime claim',
             'exe_sha256_before':before,'exe_sha256_after':after,'passed':len(records)-sum(not r['valid'] for r in records),
             'failed':len(failed),'failures':failed,'cases':records}
    (args.output/'results.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'cases':len(records),'passed':summary['passed'],'failed':summary['failed'],'failures':failed}))
    return bool(failed)

if __name__=='__main__':raise SystemExit(run())
