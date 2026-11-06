"""Independent identity and byte oracle for the fixed SQL source catalog."""
if not __debug__: raise RuntimeError("Python optimization disables required checks")
import argparse, hashlib, struct, subprocess, zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--exe',required=True,type=Path);p.add_argument('--fixtures',required=True,type=Path);a=p.parse_args()
files={name:(a.fixtures/name).read_bytes() for name in ('raw-a.dex','raw-b.dex','resource-only.apk','reverse-deflate.apk')}
expected_sha={'raw-a.dex':'dd0e9527dda007481637b6b43393a8239635e85fa006b452092dcc064c3e456f','raw-b.dex':'f0598ae1758ace8b1345d01bdb1ac237d271d431b1f633b6b65fc7835ceb9543','resource-only.apk':'cc40a323a644bdb171431693957b9fae5fb7d202ba5148e165bc723fb76052be','reverse-deflate.apk':'9f642f00cdbf46949079c417755846bb03a2843b118b35d1c1eba4b4d83d8662'}
for name,data in files.items(): assert hashlib.sha256(data).hexdigest()==expected_sha[name],name
with zipfile.ZipFile(a.fixtures/'reverse-deflate.apk') as z:
    entries={entry.filename:(index,z.read(entry)) for index,entry in enumerate(z.infolist()) if entry.filename in ('classes.dex','classes2.dex','classes10.dex')}
assert set(entries)=={'classes.dex','classes2.dex','classes10.dex'}
with zipfile.ZipFile(a.fixtures/'resource-only.apk') as z:
    assert all(i.filename not in ('classes.dex','classes2.dex','classes10.dex') for i in z.infolist())
assert entries['classes.dex'][1] == files['raw-a.dex'] and entries['classes2.dex'][1] == files['raw-b.dex'] and hashlib.sha256(entries['classes10.dex'][1]).hexdigest() == 'ba670ff08a87906ba2ca5528fd96b4dcc3c99ca314d070757d2ab12705a6c1cf'
def hash_(data): return hashlib.sha256(data).hexdigest()
def frame(s):
    b=s.encode('utf-8');return str(len(b)).encode()+b':'+b
def content(kind,data): return 'sha256:'+kind+':v1:'+str(len(data))+':'+hash_(data)
def occurrence(ns,kind,slot,role,entry,dex):
    data=b'dmg:occurrence:v2:'+b''.join(frame(x) for x in (ns,kind,slot,role,entry,content('raw-dex',dex)))
    return 'occurrence:v2:'+hash_(data)
def logical(dex): return 'logical-dex:v1:'+frame(content('raw-dex',dex)).decode()+'header-offset:0'
def I(x): return 'I'+str(x)
def T(x): return 'T'+x
def H(x): return T(x.encode().hex())
ns='catalog'; definitions=[('base','baseRole',1,files['raw-a.dex'],0,1),('duplicate','splitRole',1,files['raw-a.dex'],0,0),('resource','assets',2,files['resource-only.apk'],1,0),('apk','code',2,files['reverse-deflate.apk'],0,0)]
input_rows=[]; occurrences=[]; source_rows=[]; dexes=[]
for input_index,(slot,role,kind,data,allow,verified) in enumerate(definitions):
    num=(1 if kind==1 else (0 if allow else 3)); ident=content('raw-dex' if kind==1 else 'apk',data)
    input_rows.append([I(input_index),I(kind),T(slot),T(role),H(slot),H(role),T(hash_(data)),T(ident),I(len(data)),I(num),I(allow),I(verified),I(1)])
    selected=[('',None,data)] if kind==1 else ([] if allow else [(n,*entries[n]) for n in ('classes.dex','classes2.dex','classes10.dex')])
    for entry,index,dex in selected:
        oc=occurrence(ns,'raw-input' if kind==1 else 'archive-entry',slot,role,entry,dex);occurrences.append(oc);dexes.append(dex)
        source_rows.append([I(len(source_rows)),I(input_index),T(slot),T(role),H(slot),H(role),T(hash_(dex)),T(content('raw-dex',dex)),T(oc),T(logical(dex)),I(len(dex)),I(int(dex[4:7])),
          'N' if kind==1 else T(hash_(data)),'N' if kind==1 else T(entry),'N' if kind==1 else I(index),I(0 if kind==1 else 1),I(0 if kind==1 else 1),I(verified)])
identity=b'dmg:snapshot:source-set-v1:'+frame(ns)+frame('complete')+frame(str(len(definitions)))
for slot,role,kind,data,allow,verified in definitions:
    identity+=b''.join(frame(x) for x in (slot,role,str(kind),str(allow),content('raw-dex' if kind==1 else 'apk',data)))
identity+=frame(str(len(occurrences)))+b''.join(frame(x) for x in occurrences)
snapshot_id='snapshot:v2:'+hash_(identity)
def u32(dex,at): return struct.unpack_from('<I',dex,at)[0]
snapshot_rows=[[T(snapshot_id),T(ns),H(ns),I(1),I(4),I(5),I(sum(len(x[3]) for x in definitions)),I(sum(map(len,dexes))),I(sum(u32(x,56) for x in dexes)),I(sum(u32(x,64) for x in dexes)),I(sum(u32(x,96) for x in dexes)),I(sum(u32(x,88) for x in dexes)),I(10)]]
run=subprocess.run([str(a.exe.resolve()),str(a.fixtures.resolve())],capture_output=True,timeout=90)
if run.returncode: raise SystemExit('catalog test failed: '+run.stderr.decode('utf-8','replace')+'\n'+run.stdout.decode('utf-8','replace'))
actual={'SNAP':[],'INPUT':[],'SOURCE':[]}
for line in run.stdout.decode('utf-8').splitlines():
    fields=line.split('\t')
    if fields[0] in actual:actual[fields[0]].append(fields[1:])
assert actual['SNAP']==snapshot_rows,(actual['SNAP'],snapshot_rows)
assert actual['INPUT']==input_rows,(actual['INPUT'],input_rows)
assert actual['SOURCE']==source_rows,(actual['SOURCE'],source_rows)
assert b'PASS source catalog:' in run.stdout
print('PASS independent DEX/APK SHA, ordered occurrence and snapshot identity; 1 snapshot, 4 inputs, 5 occurrences')

