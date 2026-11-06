import json,struct,subprocess,hashlib,zlib,pathlib,sys
if len(sys.argv)!=4: raise SystemExit('usage: python class_annotation_flags_oracle.py CLI.exe FIXTURE.dex NEW_OUTPUT_DIR')
exe=sys.argv[1]; fixture=pathlib.Path(sys.argv[2]); root=pathlib.Path(sys.argv[3]); root.mkdir(parents=True,exist_ok=False); original=fixture.read_bytes()
def u32(b,p):return struct.unpack_from('<I',b,p)[0]
def leb(b,p):
 v=0
 for n in range(5):
  a=b[p];p+=1;v|=(a&127)<<(7*n)
  if a<128:return v,p
 raise ValueError('invalid uleb')
def model(b):
 ns,so=struct.unpack_from('<II',b,56); nt,to=struct.unpack_from('<II',b,64); nc,co=struct.unpack_from('<II',b,96)
 strings=[]
 for i in range(ns):
  p=u32(b,so+4*i);_,p=leb(b,p);strings.append(b[p:b.index(0,p)].decode('utf-8'))
 types=[strings[u32(b,to+4*i)] for i in range(nt)]; result={}
 for i in range(nc):
  o=co+32*i;ti,raw,_,_,_,directory=struct.unpack_from('<6I',b,o);desc=types[ti];v={'source_index':0,'class_ordinal':i,'source_kind':0,'directory_offset':directory,'set_offset':0,'item_offset':0,'value_offset':0,'raw_flags':raw,'encoded_flags':0,'projected_flags':raw&65535}
  if directory:
   v['source_kind']=1;sett=u32(b,directory);v['set_offset']=sett
   if sett:
    v['source_kind']=2
    for k in range(u32(b,sett)):
     item=u32(b,sett+4+4*k);visibility=b[item];p=item+1;typ,p=leb(b,p)
     if visibility!=2 or types[typ]!='Ldalvik/annotation/InnerClass;':continue
     size,p=leb(b,p);found=False
     for _ in range(size):
      name,p=leb(b,p);tag=b[p];at=p;p+=1;kind=tag&31;arg=tag>>5
      if kind==0x1c:
       count,p=leb(b,p);assert count==0;data=0
      elif kind in (0x1e,0x1f):data=0
      elif kind in (0,2,3,4,6,0x10,0x11,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b):data=int.from_bytes(b[p:p+arg+1],'little',signed=(kind==4));p+=arg+1
      else:raise ValueError('fixture oracle does not support nested value')
      if strings[name]=='accessFlags':
       found=True;v.update(source_kind=3,item_offset=item,value_offset=at,encoded_flags=data&0xffffffff,projected_flags=(data&0xffff) if kind==4 and data>=0 and not(data&~0x761f) and (data&7).bit_count()<=1 else None)
     if not found:v['projected_flags']=None
  result[desc]=v
 return result
records=[]
def run(name,b,old=False,where=None,relation='class_defs',max_work=None):
 path=root/(name+'.dex');path.write_bytes(b)
 q={'schema_version':1,'required_capabilities':['reflection_flags_static']+([] if old else ['reflection_class_annotations_static']),'relation':relation,'where':where or {'flags':{'domain':'reflection','mode':'contains','value':0}},'intent':'enumerate'}
 if max_work is not None:q['max_work']=max_work
 qp=root/(name+'.json');qp.write_text(json.dumps(q));argv=[exe,'query',str(path),'--query',str(qp),'--json','--dex-checksums'];p=subprocess.run(argv,capture_output=True)
 (root/(name+'-cli.stdout')).write_bytes(p.stdout);(root/(name+'-cli.stderr')).write_bytes(p.stderr)
 records.append({'case':name,'argv':argv,'exit_code':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()})
 (root/'cli-commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf8')
 if p.returncode: return p.returncode,p.stderr.decode(errors='replace')
 out=json.loads(p.stdout);(root/(name+'-out.json')).write_bytes(p.stdout);return 0,out
def repair(b):
 b=bytearray(b);b[12:32]=hashlib.sha1(b[32:]).digest();struct.pack_into('<I',b,8,zlib.adler32(b[12:])&0xffffffff);return bytes(b)
def verify(name,b):
 expected=model(b);rc,out=run(name,b);assert rc==0,(name,out)
 assert out['profile']=='dex-query-reflection-class-annotations-v20';assert out['unknown_rows']==sum(v['projected_flags'] is None for v in expected.values())
 rows=out['candidates'];assert {r['type_descriptor'] for r in rows}=={k for k,v in expected.items() if v['projected_flags'] is not None};assert len(rows)==sum(v['projected_flags'] is not None for v in expected.values())
 for row in rows:
  ev=[e['class_annotation_flags'] for e in row['evidence'] if e['kind']=='class_annotation_flags'];assert len(ev)==1; assert ev[0]==expected[row['type_descriptor']],(row['type_descriptor'],ev[0],expected[row['type_descriptor']])
 return out,expected
out,ref=verify('oracle-baseline',original)
private=ref['Lfixture/InnerFlagsCases$PrivateStatic;'];assert private['projected_flags']==10
value=private['value_offset'];access_name=original[value-1];second_name=original[value+2];assert 0<access_name<127 and access_name+1<second_name and original[value-2]==2
# Keep annotation-item size fixed by replacing its two elements with one
# accessFlags element and legal non-minimal name ULEB where needed.
for width in (2,3,4):
 for name,bits in [('positive',9),('negative',0x80 << (8*(width-1)))]:
  mut=bytearray(original);value=private['value_offset'];assert mut[value-1]==access_name and mut[value-2]==2
  mut[value-2]=1
  name_leb={2:bytes([access_name|128,0x80,0]),3:bytes([access_name|128,0]),4:bytes([access_name])}[width]
  encoded=name_leb+bytes([4|((width-1)<<5)])+bits.to_bytes(width,'little')
  assert len(encoded)==6;mut[value-1:value+5]=encoded
  _,refs=verify('oracle-int%d-%s'%(width,name),repair(mut));actual=refs['Lfixture/InnerFlagsCases$PrivateStatic;']
  assert actual['projected_flags']==(9 if name=='positive' else None)
# The second element can be a valid empty array without changing the item size.
mut=bytearray(original);value=private['value_offset'];assert mut[value+2]==second_name and mut[value+3]&31==0x17;mut[value+3:value+5]=bytes([0x1c,0]);_,nested=verify('oracle-nested-empty-array',repair(mut));assert nested['Lfixture/InnerFlagsCases$PrivateStatic;']['projected_flags']==10
# An otherwise valid top-level element with a different member name is not accessFlags.
mut=bytearray(original);mut[value-1]=access_name+1;_,missing=verify('oracle-missing-access-flags',repair(mut));assert missing['Lfixture/InnerFlagsCases$PrivateStatic;']['projected_flags'] is None
outer=ref['Lfixture/InnerFlagsCases;']
mut=bytearray(original);struct.pack_into('<I',mut,outer['directory_offset'],0);_,ref0=verify('oracle-no-class-set',repair(mut));assert ref0['Lfixture/InnerFlagsCases;']['source_kind']==1
mut=bytearray(original);class_defs=u32(mut,100);struct.pack_into('<I',mut,class_defs+32*outer['class_ordinal']+20,0);_,ref00=verify('oracle-no-directory',repair(mut));assert ref00['Lfixture/InnerFlagsCases;']['source_kind']==0
mut=bytearray(original);mut[private['item_offset']]=0;out2,ref2=verify('oracle-nonsystem',repair(mut));assert ref2['Lfixture/InnerFlagsCases$PrivateStatic;']['projected_flags']==0
mut=bytearray(original);assert mut[private['value_offset']]==4;mut[private['value_offset']]=0;out3,ref3=verify('oracle-wrongtype',repair(mut));assert ref3['Lfixture/InnerFlagsCases$PrivateStatic;']['projected_flags'] is None
mut=bytearray(original);mut[private['value_offset']+1]=128;out4,ref4=verify('oracle-unknownflags',repair(mut));assert ref4['Lfixture/InnerFlagsCases$PrivateStatic;']['projected_flags'] is None
mut=bytearray(original);mut[private['value_offset']]=255;rc,err=run('oracle-malformed',repair(mut));assert rc!=0,(rc,err)
rc,legacy=run('oracle-legacy',original,old=True);assert rc==0 and legacy['profile']=='dex-query-reflection-flags-v13' and legacy['unknown_rows']==6
rc,limited=run('oracle-budget',original,max_work=1);assert rc!=0 and 'BudgetExceeded' in limited,(rc,limited)
where={'owner_flags':{'domain':'reflection','mode':'contains','value':8}};rc,owners=run('oracle-owner',original,where=where,relation='method_defs');assert rc==0,(rc,owners)
assert all(e['class_annotation_flags']['projected_flags']&8 for row in owners['candidates'] for e in row['evidence'] if e['kind']=='class_annotation_flags')
assert any(any(e['kind']=='class_annotation_flags' for e in row['evidence']) for row in owners['candidates'])
summary={'status':'passed','scope':'independent fixed ASCII D8 fixture and targeted mutations; no ART/device/general DEX verification','fixture_sha256':hashlib.sha256(original).hexdigest(),'known_baseline':len(out['candidates']),'legacy_unknown':legacy['unknown_rows'],'owner_rows':len(owners['candidates']),'budget_status':'BudgetExceeded','mutations':['2/3/4-byte positive and negative ints','empty nested array','missing accessFlags Unknown','no directory fallback','no class set fallback','non-system fallback','wrong value type unknown','invalid flag bits unknown','malformed value rejected']}
(root/'oracle-summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
