"""Independent byte scan for the exact-literal, no-argument return-type method profile.

This intentionally rejects other query shapes instead of pretending to verify them.
Opcode widths are factual format data pinned independently to AOSP; no native reader is called.
"""
from pathlib import Path
import argparse,hashlib,json,re,struct,zipfile

def u16(data,at):return struct.unpack_from('<H',data,at)[0]
def u32(data,at):return struct.unpack_from('<I',data,at)[0]
def leb(data,at):
 value=0
 for i in range(5):
  if at>=len(data):raise ValueError('truncated ULEB')
  b=data[at];at+=1
  if i==4 and b&0xf0:raise ValueError('ULEB overflow')
  value|=(b&127)<<(7*i)
  if not b&128:return value,at
 raise ValueError('bad ULEB')
def units(data,index):
 if index>=u32(data,56):raise ValueError('string index outside table')
 at=u32(data,u32(data,60)+4*index);count,at=leb(data,at);out=[]
 for _ in range(count):
  a=data[at];at+=1
  if 0<a<128:value=a
  elif a&224==192:
   b=data[at];at+=1
   if b&192!=128:raise ValueError('bad MUTF continuation')
   value=((a&31)<<6)|(b&63)
   if value<128 and (a,b)!=(192,128):raise ValueError('overlong MUTF')
  elif a&240==224:
   b,c=data[at:at+2];at+=2
   if b&192!=128 or c&192!=128:raise ValueError('bad MUTF continuation')
   value=((a&15)<<12)|((b&63)<<6)|(c&63)
   if value<2048:raise ValueError('overlong MUTF')
  else:raise ValueError('bad MUTF lead')
  out.append(value)
 if data[at]!=0:raise ValueError('MUTF terminator mismatch')
 return tuple(out)
def unit_text(value):return b''.join(struct.pack('<H',c) for c in value).decode('utf-16le',errors='surrogatepass')
def find_string(data,wanted):
 lo,hi=0,u32(data,56)
 while lo<hi:
  middle=(lo+hi)//2
  if units(data,middle)<wanted:lo=middle+1
  else:hi=middle
 return lo if lo<u32(data,56) and units(data,lo)==wanted else None
def type_name(data,index):return unit_text(units(data,u32(data,u32(data,68)+4*index)))
def definitions(data):
 declared=set()
 for cls in range(u32(data,96)):
  at=u32(data,u32(data,100)+32*cls+24)
  if not at:continue
  sizes=[]
  for _ in range(4):value,at=leb(data,at);sizes.append(value)
  for amount in sizes[:2]:
   for _ in range(amount):_,at=leb(data,at);_,at=leb(data,at)
  for amount in sizes[2:]:
   index=0
   for _ in range(amount):
    declaration=at;delta,at=leb(data,at);index+=delta;flags,at=leb(data,at);code,at=leb(data,at)
    if index>=u32(data,88) or index in declared:raise ValueError('bad definition index')
    declared.add(index);yield index,declaration,flags,code
def scan_code(data,offset,string_index,widths):
 count=u32(data,offset+12);start=offset+16
 if start+2*count>len(data):raise ValueError('code range outside DEX')
 pc=0;matches=[]
 while pc<count:
  word=u16(data,start+2*pc);op=word&255
  if op==0 and word:
   kind=word>>8
   if kind==1:width=4+2*u16(data,start+2*(pc+1))
   elif kind==2:width=2+4*u16(data,start+2*(pc+1))
   elif kind==3:width=4+(u16(data,start+2*(pc+1))*u32(data,start+2*(pc+2))+1)//2
   else:raise ValueError('unknown payload')
  else:
   width=widths[op]
   if width==0:raise ValueError('reserved opcode prevents complete scan')
  if pc+width>count:raise ValueError('truncated instruction/payload')
  if op in (0x1a,0x1b):
   index=u16(data,start+2*(pc+1)) if op==0x1a else u32(data,start+2*(pc+1))
   if index>=u32(data,56):raise ValueError('bad string use')
   if index==string_index:matches.append({'dex_pc':pc,'opcode':op,'reference_index':index})
  pc+=width
 return matches
def canonical_query_id(query,literal,returned):
 if not set(query)<= {'schema_version','relation','where','intent','max_results','max_work','evidence_profile'}:raise ValueError('unsupported normalization shape')
 if query.get('evidence_profile','minimal')!='minimal':raise ValueError('unsupported evidence profile')
 p32=lambda v:struct.pack('<I',v);p64=lambda v:struct.pack('<Q',v)
 def text(value):
  raw=value.encode('utf-16le',errors='surrogatepass')
  return p32(1)+p32(0)+p32(0)+p64(len(raw)//2)+raw
 def node(kind,value=None,maximum=0xffffffff):return p32(kind)+(p32(0) if value is None else text(value))+p32(0)+p32(0)+p32(maximum)+p32(0)
 children=sorted([node(8,returned),node(9,maximum=0),node(14,literal)])
 root=p32(2)+p32(0)+p32(0)+p32(0)+p32(0xffffffff)+p32(3)+b''.join(p64(len(c))+c for c in children)
 encoded=b'DexMeguviz:QueryIR:method-v1'+p32(2)+p32(query.get('max_results',4096))+p64(query.get('max_work',100000000))+p32(7)+p32(0)+p32(0)+p32(39)+p32(0)+p32(0)+root
 return 'query:v1:'+hashlib.sha256(encoded).hexdigest()

def verify(run_directory:Path,root:Path):
 run=json.loads((run_directory/'run.json').read_text(encoding='utf-8'))
 result=json.loads((run_directory/'stdout.json').read_text(encoding='utf-8'))
 args=run['command'];query_path=Path(args[args.index('--query')+1]);query=json.loads(query_path.read_text(encoding='utf-8'))
 where=query['where']
 if set(where)!={'return_type','parameters','using_strings'} or where['parameters']!=[] or query['relation']!='method_defs' or query['intent']!='unique':raise ValueError('unsupported independent query shape')
 patterns=where['using_strings']
 if set(patterns)!={'all'} or len(patterns['all'])!=1:raise ValueError('expected one all/exact literal')
 literal=patterns['all'][0]
 if isinstance(literal,str):value=literal
 elif set(literal)=={'op','value'} and literal['op']=='exact':value=literal['value']
 else:raise ValueError('unsupported independent text semantics')
 returned=where['return_type']
 if not isinstance(returned,str):raise ValueError('expected exact return descriptor')
 assert result['query_id']==canonical_query_id(query,value,returned)
 wanted=tuple(struct.unpack('<'+'H'*(len(value.encode('utf-16le',errors='surrogatepass'))//2),value.encode('utf-16le',errors='surrogatepass')))
 table=json.loads((root/'tests/fixtures/generated/instructions/opcode_widths.json').read_text())
 widths=[0]*256
 for row in table['rows']:widths[row['opcode']]=row['width']
 if run['exit_code']!=0 or result['execution_status']!='Complete' or not result['scope_complete']:raise ValueError('query did not complete a full declared source set')
 if len(result['inputs'])!=1 or result['inputs'][0]['format']!='Apk':raise ValueError('this verifier requires one complete APK')
 apk=Path(args[2]);assert hashlib.sha256(apk.read_bytes()).hexdigest()==result['inputs'][0]['source_sha256']
 matches=[];declared_count=0;methods_scanned=0;source_reports=[]
 with zipfile.ZipFile(apk) as archive:
  names=[x.filename for x in archive.infolist() if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex',x.filename)]
  names.sort(key=lambda n:1 if n=='classes.dex' else int(n[7:-4]))
  assert names==[s['archive_entry_name'] for s in result['sources']]
  for source in result['sources']:
   data=archive.read(source['archive_entry_name']);assert hashlib.sha256(data).hexdigest()==source['source_sha256']
   marker=find_string(data,wanted);local_count=0;source_scans=0
   for index,at,flags,code in definitions(data):
    local_count+=1
    if marker is None or not code:continue
    ref=u32(data,92)+8*index;owner,proto,name=struct.unpack_from('<HHI',data,ref);prototype=u32(data,76)+12*proto
    params=u32(data,prototype+8)
    if params and u32(data,params)!=0:continue
    if type_name(data,u32(data,prototype+4))!=returned:continue
    source_scans+=1;uses=scan_code(data,code,marker,widths)
    if uses:matches.append({'source_index':source['source_index'],'method_index':index,'declaration_offset':at,'access_flags':flags,'code_offset':code,'owner':type_name(data,owner),'name':unit_text(units(data,name)),'prototype':'()'+returned,'string_uses':uses})
   assert local_count==source['counts']['method_defs'];declared_count+=local_count;methods_scanned+=source_scans
   source_reports.append({'entry':source['archive_entry_name'],'source_sha256':source['source_sha256'],'literal_index':marker,'declarations':local_count,'eligible_bodies_scanned':source_scans})
 assert declared_count==result['total_methods']
 expected={(m['source_index'],m['method_index']):m for m in matches}
 for candidate in result['candidates']:
  key=(candidate['source_index'],candidate['method_index']);assert key in expected;actual=expected[key]
  for field in ['declaration_offset','access_flags','code_offset','owner','name','prototype']:assert candidate[field]==actual[field]
  uses=[w for w in candidate['evidence'] if w['kind']=='string_use' and w['matched']]
  assert uses and all({k:w[k] for k in ['dex_pc','opcode','reference_index']} in actual['string_uses'] for w in uses)
 if len(matches)==1:assert result['decision']=='ProvenTrue' and result['coverage']=='Complete' and len(result['candidates'])==1
 elif not matches:assert result['decision']=='ProvenFalse' and result['reason']=='NoMatch' and result['coverage']=='Complete'
 else:assert result['decision']=='ProvenFalse' and result['reason']=='Ambiguous' and len(result['candidates'])==2
 report={'passed':True,'scope':'Independent full declared method scan and canonical QueryID for this exact-literal/return/no-argument profile; no native decoder or native cache reused','query_sha256':hashlib.sha256(query_path.read_bytes()).hexdigest(),'query_id':result['query_id'],'opcode_width_reference_sha256':hashlib.sha256((root/'tests/fixtures/generated/instructions/opcode_widths.json').read_bytes()).hexdigest(),'literal':value,'return_type':returned,'declared_methods':declared_count,'eligible_bodies_scanned':methods_scanned,'matches':matches,'sources':source_reports,'not_proven':['ART runtime validity','ClassLoader/Hook binding','performance','other QueryIR predicates']}
 (run_directory/'independent-literal-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 return {k:v for k,v in report.items() if k!='sources'}

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--run',type=Path,required=True);parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);a=parser.parse_args()
 print(json.dumps(verify(a.run,a.root),ensure_ascii=False,indent=2))
