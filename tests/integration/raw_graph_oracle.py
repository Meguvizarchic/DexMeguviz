"""Independent byte-level oracle for generated DEX graph fixtures.

Only understands this authored fixture grammar. Does not run the proposed
BoundedExpand implementation and makes no ART/runtime verification claim.
"""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import struct
import zlib

PINS={
 'amb-a.dex':'10d0ea04da45c7c021ba902ce90ea8f24415d44fd396916088ed55dc6518213b',
 'amb-b1.dex':'c811692d62f01e48bb23d83edb7c642501be7d7e6f1c7bceb6abacb80558371f',
 'amb-b2.dex':'c605e9132c416a210acc409890c6003ac3228e7b03553397834c057f170e45a4',
 'amb-c1.dex':'97a56d6392561486cf27ce7270362cc1b23b8481468c5a2e1522bb03808dd8b6',
 'amb-c2.dex':'9e132bb4c1ab74db8a6802c0ed364adc534e32982adbb0c68071a6fbb211bee9',
 'amb-overload.dex':'c0fab422a2f5706321bf77eab534c0da353705a3e260663a0829be23f09d7d0e',
 'cycle-a.dex':'79d75f4435aa890de3e3942615b8be80b09836b55d85d5ad29fafd70fdc584df',
 'cycle-b.dex':'005f5ccea3544eb6c2759a3ab0bff5e20df12efac7c28536173cf09f5f2921be',
 'diamond-a.dex':'1da956c8aed19f47711c1a5d2e8e885d98769872b57cd78ffd134a103e8f609a',
 'diamond-b.dex':'71f26ad76c71a7ffa3cce7a6d4649bf85c70874cbd6daa4313fc3e09d9726f79',
 'diamond-c.dex':'319ceb42ae8d25077d8991147dcbdda6add577868c8df9951a545f356dde1975',
 'diamond-d.dex':'11f93469220a30a85519c6b48d3a2b2f8f11b54ddadb4ce26a0b8402a33b04c0',
}
EXPECTED={
 'amb-a.dex':(('Lamb/A;','a','()V'),[(0,('Lamb/B;','b','()V')),(3,('Lamb/B;','b','()V'))]),
 'amb-b1.dex':(('Lamb/B;','b','()V'),[(0,('Lamb/C1;','c','()V'))]),
 'amb-b2.dex':(('Lamb/B;','b','()V'),[(0,('Lamb/C2;','c','()V'))]),
 'amb-c1.dex':(('Lamb/C1;','c','()V'),[]),'amb-c2.dex':(('Lamb/C2;','c','()V'),[]),
 'amb-overload.dex':(('Lamb/B;','b','(I)V'),[]),
 'cycle-a.dex':(('Lcycle/A;','a','()V'),[(0,('Lcycle/B;','b','()V'))]),
 'cycle-b.dex':(('Lcycle/B;','b','()V'),[(0,('Lcycle/A;','a','()V'))]),
 'diamond-a.dex':(('Ldiamond/A;','a','()V'),[(0,('Ldiamond/B;','b','()V')),(3,('Ldiamond/C;','c','()V'))]),
 'diamond-b.dex':(('Ldiamond/B;','b','()V'),[(0,('Ldiamond/D;','d','()V'))]),
 'diamond-c.dex':(('Ldiamond/C;','c','()V'),[(0,('Ldiamond/D;','d','()V'))]),
 'diamond-d.dex':(('Ldiamond/D;','d','()V'),[]),
}

def need(ok,message):
    if not ok:raise AssertionError(message)
def u16(data,at):
    need(0<=at<=len(data)-2,'u16 boundary');return struct.unpack_from('<H',data,at)[0]
def u32(data,at):
    need(0<=at<=len(data)-4,'u32 boundary');return struct.unpack_from('<I',data,at)[0]
def leb(data,pos):
    value=0
    for i in range(5):
        need(pos<len(data),'truncated ULEB');b=data[pos];pos+=1
        need(i<4 or b<=15,'ULEB overflow');value|=(b&127)<<(7*i)
        if not b&128:return value,pos
    raise AssertionError('overlong ULEB')

def parse(path):
    data=path.read_bytes();need(hashlib.sha256(data).hexdigest()==PINS[path.name],'fixture SHA mismatch')
    need(data[:8]==b'dex\n035\0' and u32(data,32)==len(data) and u32(data,36)==112,'header mismatch')
    need(data[12:32]==hashlib.sha1(data[32:]).digest() and u32(data,8)==zlib.adler32(data[12:])&0xffffffff,'checksum mismatch')
    count,off=u32(data,56),u32(data,60);strings=[]
    for i in range(count):
        size,p=leb(data,u32(data,off+4*i));end=data.find(b'\0',p);need(end>=p,'string terminator')
        raw=data[p:end];need(len(raw)==size and all(0<c<128 for c in raw),'non fixture ASCII');strings.append(raw.decode('ascii'))
    count,off=u32(data,64),u32(data,68);types=[strings[u32(data,off+i*4)] for i in range(count)]
    count,off=u32(data,72),u32(data,76);protos=[]
    for i in range(count):
        at=off+i*12;ret=types[u32(data,at+4)];list_off=u32(data,at+8);params=[]
        if list_off:
            for j in range(u32(data,list_off)):params.append(types[u16(data,list_off+4+j*2)])
        protos.append('('+''.join(params)+')'+ret)
    count,off=u32(data,88),u32(data,92);methods=[]
    for i in range(count):
        at=off+i*8;methods.append((types[u16(data,at)],strings[u32(data,at+4)],protos[u16(data,at+2)]))
    need(u32(data,96)==1,'expected one class');class_at=u32(data,100);owner=types[u32(data,class_at)]
    cursor=u32(data,class_at+24);sizes=[]
    for _ in range(4):n,cursor=leb(data,cursor);sizes.append(n)
    need(sizes==[0,0,1,0],'expected one direct method');method_id,cursor=leb(data,cursor);flags,cursor=leb(data,cursor);code,cursor=leb(data,cursor)
    need(method_id<len(methods) and methods[method_id][0]==owner and flags==9 and code!=0,'method definition mismatch')
    units=u32(data,code+12);need(code+16+2*units<=len(data),'code bounds')
    words=[u16(data,code+16+2*i) for i in range(units)];calls=[];pc=0
    while pc<len(words):
        if words[pc]==0x000e:need(pc==len(words)-1,'return placement');pc+=1;break
        need(pc+2<len(words) and words[pc]==0x0071 and words[pc+2]==0,'unexpected fixture opcode')
        target=words[pc+1];need(target<len(methods),'method ref bound')
        calls.append({'pc':pc,'opcode':0x71,'method_ref':target,'symbol':methods[target]});pc+=3
    need(pc==len(words),'unparsed instruction');definition=methods[method_id]
    expected_def,expected_calls=EXPECTED[path.name]
    need(definition==expected_def and [(x['pc'],x['symbol']) for x in calls]==expected_calls,'manual expected bytes mismatch')
    return {'file':path.name,'sha256':PINS[path.name],'definition':definition,'method_ref':method_id,'definition_ordinal':0,'code_offset':code,'calls':calls}

def dataset(fixtures,entries):
    return [{'occurrence':name,**parse(fixtures/file)} for name,file in entries]

def edges(items):
    out=[]
    for caller in items:
        for call in caller['calls']:
            matches=[x for x in items if x['definition']==call['symbol']]
            for target in matches:
                out.append({'caller':caller['occurrence'],'pc':call['pc'],'opcode':call['opcode'],
                    'method_ref':call['method_ref'],'symbol':call['symbol'],'target':target['occurrence'],
                    'target_method_ref':target['method_ref'],'candidate_count':len(matches)})
    return out

def paths(items,start,depth):
    all_edges=edges(items);pending=[(start,[])];output=[]
    while pending:
        current,hops=pending.pop(0)
        if len(hops)==depth:output.append(hops);continue
        for edge in all_edges:
            if edge['caller']==current:pending.append((edge['target'],hops+[edge]))
    return output

def validate_path(items,start,path):
    legal=edges(items);current=start
    for hop in path:
        if hop not in legal or hop['caller']!=current:return False
        current=hop['target']
    return True

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--fixtures',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    need(set(PINS)==set(EXPECTED),'pin/expectation mismatch')
    parsed={name:parse(args.fixtures/name) for name in PINS}
    amb_entries=[('a','amb-a.dex'),('b1','amb-b1.dex'),('b2','amb-b2.dex'),('c1','amb-c1.dex'),('c2','amb-c2.dex'),('overload','amb-overload.dex')]
    amb=dataset(args.fixtures,amb_entries);two=paths(amb,'a',2)
    normalized={(p[0]['pc'],p[0]['target'],p[1]['pc'],p[1]['target']) for p in two}
    need(normalized=={(0,'b1',0,'c1'),(3,'b1',0,'c1'),(0,'b2',0,'c2'),(3,'b2',0,'c2')} and len(two)==4,'ambiguous paths')
    need(all(p[0]['candidate_count']==2 and p[1]['candidate_count']==1 for p in two),'ambiguous candidate count')
    need({p[-1]['target'] for p in two}=={'c1','c2'},'ambiguous endpoint set')
    repeated=dataset(args.fixtures,amb_entries[:2]+[('b1-copy','amb-b1.dex')]+amb_entries[2:])
    repeated_paths=paths(repeated,'a',2);need(len(repeated_paths)==6,'occurrence duplicates')
    need(all(p[0]['candidate_count']==3 for p in repeated_paths),'repeated ambiguity count')
    cycle=dataset(args.fixtures,[('ca','cycle-a.dex'),('cb','cycle-b.dex')])
    need([[x['target'] for x in p] for p in paths(cycle,'ca',2)]==[['cb','ca']],'cycle depth2')
    need([[x['target'] for x in p] for p in paths(cycle,'ca',3)]==[['cb','ca','cb']],'cycle depth3')
    need(paths(cycle,'ca',0)==[[]],'depth zero')
    diamond=dataset(args.fixtures,[('da','diamond-a.dex'),('db','diamond-b.dex'),('dc','diamond-c.dex'),('dd','diamond-d.dex')]);dp=paths(diamond,'da',2)
    need({(p[0]['pc'],p[0]['target'],p[1]['target']) for p in dp}=={(0,'db','dd'),(3,'dc','dd')} and len(dp)==2,'diamond path multiplicity')
    need({p[-1]['target'] for p in dp}=={'dd'},'diamond endpoint set')
    incoming=[e for e in edges(amb) if e['target']=='b1'];need([(e['caller'],e['pc']) for e in incoming]==[('a',0),('a',3)],'incoming all scope')
    forged=[]
    for label,change in [('wrong-pc',lambda p:p[0].__setitem__('pc',1)),('wrong-source',lambda p:p[0].__setitem__('caller','b2')),('wrong-target',lambda p:p[0].__setitem__('target','overload')),('wrong-ref',lambda p:p[0].__setitem__('method_ref',65535)),('wrong-candidate-count',lambda p:p[0].__setitem__('candidate_count',1)),('wrong-path-order',lambda p:p.reverse())]:
        fake=copy.deepcopy(two[0]);change(fake);need(not validate_path(amb,'a',fake),'forged path accepted: '+label);forged.append(label)
    result={'scope':'authored DEX byte oracle; no BoundedExpand implementation, ART, runtime dispatch or verifier claim',
        'fixture_count':len(parsed),'raw_fixtures':parsed,'ambiguous_paths':two,'ambiguous_endpoints':['c1','c2'],
        'repeated_occurrence_paths':repeated_paths,'cycle_depth2':paths(cycle,'ca',2),'cycle_depth3':paths(cycle,'ca',3),
        'diamond_paths':dp,'diamond_endpoints':['dd'],'incoming_b1':incoming,'forged_controls_rejected':forged}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=True,indent=2);f.write('\n')
    print(json.dumps({'fixtures':len(parsed),'ambiguous_paths':len(two),'repeated_occurrence_paths':len(repeated_paths),'cycle_depth2':1,'cycle_depth3':1,'diamond_paths':len(dp),'forged_rejected':len(forged)}))

if __name__=='__main__':main()
