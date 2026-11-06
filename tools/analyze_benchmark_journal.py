#!/usr/bin/env python3
"""Recover an append-only benchmark journal into fail-closed analyzer input.

The journal and all evidence files remain untouched. Incomplete or corrupt tails
are represented by a failing record; no result authenticity is inferred.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, os, re, stat, struct, sys
from pathlib import Path

MAX_FILE=120*1024*1024
MAX_PAYLOAD=32*1024*1024
MAX_LINE=((MAX_PAYLOAD+2)//3)*4+512
MAX_FRAMES=100000
HEX=re.compile(r"[0-9a-f]{64}\Z")
CAMPAIGN=re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

def no_links(path:Path):
    path=Path(os.path.abspath(path))
    for part in (path,*path.parents):
        try: st=part.lstat()
        except FileNotFoundError: continue
        if stat.S_ISLNK(st.st_mode) or getattr(st,'st_file_attributes',0)&0x400:
            raise ValueError('symbolic link or reparse point')
    return path

def read_stable(path:Path)->bytes:
    path=no_links(path)
    with path.open('rb') as f:
        before=os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>MAX_FILE:raise ValueError('journal is not a bounded regular file')
        data=f.read(MAX_FILE+1);after=os.fstat(f.fileno())
        if len(data)>MAX_FILE or len(data)!=before.st_size or (before.st_size,before.st_mtime_ns,before.st_ino)!=(after.st_size,after.st_mtime_ns,after.st_ino):raise ValueError('journal changed during read')
    return data

def pairs(items):
    out={}
    for k,v in items:
        if k in out:raise ValueError('duplicate JSON key')
        out[k]=v
    return out

def parse_json(data:bytes):
    return json.loads(data.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite JSON number')))

def digest(value:bytes)->str:return hashlib.sha256(value).hexdigest()

def parse_frame(line:bytes,seq:int,previous:bytes):
    if len(line)>MAX_LINE:raise ValueError('frame size limit')
    obj=parse_json(line)
    if not isinstance(obj,dict) or set(obj)!={'seq','kind','previous','payload_b64','sha256'}:raise ValueError('frame shape')
    if type(obj['seq']) is not int or obj['seq']!=seq:raise ValueError('frame sequence')
    kind=obj['kind']
    if kind not in ('header','record','error','footer') or obj['previous']!=previous.hex() or not isinstance(obj['sha256'],str) or not HEX.fullmatch(obj['sha256']):raise ValueError('frame metadata')
    if not isinstance(obj['payload_b64'],str):raise ValueError('frame payload type')
    payload=base64.b64decode(obj['payload_b64'],validate=True)
    if base64.b64encode(payload).decode('ascii')!=obj['payload_b64']:raise ValueError('noncanonical base64')
    if len(payload)>MAX_PAYLOAD:raise ValueError('payload size limit')
    actual=hashlib.sha256(previous+struct.pack('>Q',seq)+kind.encode('ascii')+b'\0'+payload).digest()
    if actual.hex()!=obj['sha256']:raise ValueError('frame hash mismatch')
    return kind,payload,actual

def convert(data:bytes):
    if not data:raise ValueError('empty journal')
    records=[]; previous=bytes(32); seq=0; offset=0; header=None; gates={}; footer=False; failures=[]
    while offset<len(data):
        if seq>=MAX_FRAMES:
            failures.append(('frame_limit',offset));break
        end=data.find(b'\n',offset)
        if end<0:
            failures.append(('incomplete_frame',offset));break
        line=data[offset:end]
        try:
            kind,payload,newhash=parse_frame(line,seq,previous)
            if seq==0:
                if kind!='header':raise ValueError('first frame is not header')
                parts=payload.split(b'\n',4)
                if len(parts)!=5:raise ValueError('header shape')
                data_kind,campaign,protocol_hash,identity_hash=(x.decode('ascii') for x in parts[:4])
                if data_kind not in ('real','synthetic_control') or not CAMPAIGN.fullmatch(campaign) or not HEX.fullmatch(protocol_hash) or not HEX.fullmatch(identity_hash):raise ValueError('header fields')
                identity=parse_json(parts[4])
                if not isinstance(identity,dict):raise ValueError('identity must be object')
                header={'data_kind':data_kind,'campaign_id':campaign,'protocol_sha256':protocol_hash,'identity':identity,'identity_sha256':identity_hash}
                canonical=json.dumps(identity,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
                if digest(canonical)!=identity_hash:failures.append(('identity_digest_mismatch',offset))
            else:
                if footer:raise ValueError('frame after footer')
                if kind=='record':
                    obj=parse_json(payload)
                    if not isinstance(obj,dict):raise ValueError('record must be object')
                    records.append(obj)
                elif kind=='error':
                    error=payload.decode('utf-8')
                    if not re.fullmatch(r'[A-Za-z0-9_.$]{1,256}',error):raise ValueError('error class')
                    records.append({'complete':False,'status':'journal_serialization_error','journal_error_class':error})
                    failures.append(('serialization_error',offset))
                elif kind=='footer':
                    gates=parse_json(payload)
                    if not isinstance(gates,dict):raise ValueError('external gates must be object')
                    footer=True
                else:raise ValueError('unexpected header')
        except (ValueError,UnicodeError,TypeError,OverflowError,RecursionError) as e:
            if header is None:raise ValueError('invalid journal header: '+str(e)) from e
            failures.append(('invalid_frame:'+str(e),offset));break
        previous=newhash;seq+=1;offset=end+1
    if header is None:raise ValueError('missing valid header')
    if not footer:failures.append(('missing_footer',offset))
    if failures:
        tail=data[offset:]
        records.append({'complete':False,'status':'journal_incomplete_or_invalid','journal_failures':[x[0] for x in failures],
                        'unverified_tail_bytes':len(tail),'unverified_tail_sha256':digest(tail)})
    raw={'schema_version':1,'data_kind':header['data_kind'],'campaign_id':header['campaign_id'],
         'protocol_sha256':header['protocol_sha256'],'identity':header['identity'],'records':records,
         'external_gate_evidence':gates if footer else {},'journal_integrity':{'status':'complete' if not failures else 'incomplete_or_invalid',
         'validated_frames':seq,'source_sha256':digest(data),'last_frame_sha256':previous.hex(),'failures':[x[0] for x in failures],
         'scope':'integrity check only; caller facts and original journal are not authenticated'}}
    return raw,not failures

def save_new(path:Path,raw:dict):
    path=no_links(path);parent=path.parent
    if not parent.is_dir():raise ValueError('output parent must exist')
    payload=(json.dumps(raw,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode('utf-8')
    if len(payload)>128*1024*1024:raise ValueError('analyzer input exceeds limit')
    with path.open('xb') as f:
        f.write(payload);f.flush();os.fsync(f.fileno())
    return digest(payload)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--journal',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if no_links(a.journal)==no_links(a.output):raise ValueError('output must differ from source')
    data=read_stable(a.journal);raw,complete=convert(data);out_hash=save_new(a.output,raw)
    print(json.dumps({'status':'journal_complete_not_authenticated' if complete else 'journal_incomplete_or_invalid','validated_frames':raw['journal_integrity']['validated_frames'],'records':len(raw['records']),'journal_sha256':digest(data),'output_sha256':out_hash},separators=(',',':')))
    return 0 if complete else 2
if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,TypeError,UnicodeError,RecursionError,OverflowError) as e:
        print(json.dumps({'status':'conversion_failed','reason':str(e)}),file=sys.stderr);sys.exit(1)
