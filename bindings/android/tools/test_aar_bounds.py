"""Deterministic bounds checks for the fixed AAR audit; outputs are retained."""
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
import argparse,hashlib,io,json,struct,subprocess,sys

from verify_aar import AAR_BYTES,AAR_ENTRIES,AAR_MEMBER,JAR_BYTES,JAR_ENTRIES,JAR_MEMBER,TEXT_MEMBER


def patch_sizes(data,updates):
    data=bytearray(data);end=data.rfind(b'PK\x05\x06')
    if end<0 or end+22>len(data):raise ValueError('missing end of central directory')
    count=struct.unpack_from('<H',data,end+10)[0]
    pos=struct.unpack_from('<I',data,end+16)[0]
    pending=dict(updates)
    for _ in range(count):
        if data[pos:pos+4]!=b'PK\x01\x02':raise ValueError('invalid central directory')
        name_size,extra_size,comment_size=struct.unpack_from('<HHH',data,pos+28)
        name=bytes(data[pos+46:pos+46+name_size]).decode('utf-8')
        if name in pending:
            struct.pack_into('<I',data,pos+24,pending.pop(name))
        pos+=46+name_size+extra_size+comment_size
    if pending:raise ValueError('central entries missing: '+repr(pending))
    return bytes(data)


def add_entries(data,entries):
    output=io.BytesIO()
    with ZipFile(io.BytesIO(data)) as old,ZipFile(output,'w') as new:
        for item in old.infolist():new.writestr(item,old.read(item))
        for name in entries:new.writestr(name,b'x')
    return output.getvalue()


def add_real_compressed_member(data,name,size):
    output=io.BytesIO()
    with ZipFile(io.BytesIO(data)) as old,ZipFile(output,'w') as new:
        for item in old.infolist():new.writestr(item,old.read(item))
        new.writestr(name,bytes(size),compress_type=ZIP_DEFLATED)
    return output.getvalue()


def replace_jar(original,jar):
    output=io.BytesIO()
    with ZipFile(io.BytesIO(original)) as old,ZipFile(output,'w') as new:
        for item in old.infolist():new.writestr(item,jar if item.filename=='classes.jar' else old.read(item))
    return output.getvalue()


def corrupt_member(data,name):
    with ZipFile(io.BytesIO(data)) as archive:info=archive.getinfo(name)
    output=bytearray(data);at=info.header_offset
    if output[at:at+4]!=b'PK\x03\x04':raise ValueError('missing local ZIP header')
    name_size,extra_size=struct.unpack_from('<HH',output,at+26)
    start=at+30+name_size+extra_size
    if not info.compress_size:raise ValueError('empty compressed stream')
    output[start:start+info.compress_size]=bytes([0xff])*info.compress_size
    return bytes(output)


def main():
    p=argparse.ArgumentParser()
    for name in ('aar','header','readelf','runtime-report','out'):p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    original=args.aar.read_bytes();script=Path(__file__).with_name('verify_aar.py')
    with ZipFile(io.BytesIO(original)) as archive:jar=archive.read('classes.jar')
    cases=[]
    def add(label,data,diagnostic):
        path=args.out/(label+'.aar');path.write_bytes(data);cases.append((label,path,diagnostic))
    add('aar-member',patch_sizes(add_entries(original,['assets/large.bin']),{'assets/large.bin':AAR_MEMBER+1}),'AAR entry exceeds decompression limit')
    names=['assets/large'+str(i)+'.bin' for i in range(5)]
    add('aar-total',patch_sizes(add_entries(original,names),{n:AAR_MEMBER for n in names}),'AAR aggregate exceeds decompression limit')
    add('aar-entries',add_entries(original,['assets/empty'+str(i) for i in range(AAR_ENTRIES)]),'AAR has too many entries')
    add('jar-compressed-entry',patch_sizes(original,{'classes.jar':JAR_BYTES+1}),'entry exceeds decompression limit: classes.jar')
    add('manifest-entry',patch_sizes(original,{'AndroidManifest.xml':TEXT_MEMBER+1}),'entry exceeds decompression limit: AndroidManifest.xml')
    jar1=patch_sizes(add_entries(jar,['extras/large.bin']),{'extras/large.bin':JAR_MEMBER+1})
    add('jar-member',replace_jar(original,jar1),'classes.jar entry exceeds decompression limit')
    real=add_real_compressed_member(jar,'extras/compressed-large.bin',JAR_MEMBER+1)
    add('jar-member-real',replace_jar(original,real),'classes.jar entry exceeds decompression limit')
    names=['extras/large'+str(i)+'.bin' for i in range(9)]
    jar2=patch_sizes(add_entries(jar,names),{n:JAR_MEMBER for n in names})
    add('jar-total',replace_jar(original,jar2),'classes.jar aggregate exceeds decompression limit')
    jar3=add_entries(jar,['extras/empty'+str(i) for i in range(JAR_ENTRIES)])
    add('jar-entries',replace_jar(original,jar3),'classes.jar has too many entries')
    add('corrupted-compressed-data',corrupt_member(original,'AndroidManifest.xml'),'invalid or unsupported AAR input:')
    add('truncated-container',original[:-30],'invalid or unsupported AAR input:')
    raw=args.out/'oversized-raw.aar'
    with raw.open('xb') as f:f.seek(AAR_BYTES);f.write(b'x')
    cases.append(('aar-file',raw,'input file exceeds audit size limit'))
    records=[]
    for label,path,diagnostic in cases:
        cmd=[sys.executable,'-B',str(script),'--aar',str(path),'--header',str(args.header),
             '--readelf',str(args.readelf),'--runtime-report',str(args.runtime_report),'--out',str(args.out/(label+'-check'))]
        result=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90)
        (args.out/(label+'.stdout.log')).write_text(result.stdout,encoding='utf-8')
        (args.out/(label+'.stderr.log')).write_text(result.stderr,encoding='utf-8')
        record={'case':label,'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                'exit_code':result.returncode,'stderr':result.stderr.strip(),'expected_diagnostic':diagnostic}
        records.append(record)
        if result.returncode==0 or diagnostic not in result.stderr:raise SystemExit('unexpected bounds result: '+repr(record))
    (args.out/'records.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
    print('PASS',len(records),'AAR/JAR bounds and malformed inputs rejected with expected diagnostics')


if __name__=='__main__':main()
