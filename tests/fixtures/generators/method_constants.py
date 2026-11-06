from pathlib import Path
import argparse,hashlib,importlib.util,json,struct,zlib
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--builder',type=Path,required=True);a=p.parse_args();assert not a.out.exists();a.out.mkdir(parents=True);base=a.input.read_bytes();assert hashlib.sha256(base).hexdigest()=='ecf85d163c87d58f065335f0d932442be48b91b5efa3858e319a1c1cdf7313b0';assert struct.unpack_from('<HHHHII',base,416)==(1,0,1,0,0,8)
words=(0x00fe,0,0x00ff,0,0x00fe,0,0x000e,0);data=bytearray(base);data[4:7]=b'039';struct.pack_into('<8H',data,432,*words)
def fix(d):d[12:32]=hashlib.sha1(d[32:]).digest();struct.pack_into('<I',d,8,zlib.adler32(d[12:])&0xffffffff)
variants={'good-039':data}
def change(name,edit):d=bytearray(data);edit(d);variants[name]=d
change('good-040',lambda d:d.__setitem__(slice(4,7),b'040'))
change('old-038',lambda d:d.__setitem__(slice(4,7),b'038'))
change('bad-handle',lambda d:struct.pack_into('<H',d,434,1))
change('bad-type',lambda d:struct.pack_into('<H',d,438,1))
change('bad-register',lambda d:struct.pack_into('<H',d,432,0x01fe))
change('late-opcode',lambda d:struct.pack_into('<H',d,446,0x0073))
spec=importlib.util.spec_from_file_location('fixture_builder',a.builder);builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder);original=bytearray(builder.build('Lconstant/Subject;','uses','V',[],used=['probe','probe','probe'],extra_native=[('other','I',[],0x109)]));oldmap=struct.unpack_from('<I',original,52)[0];n=struct.unpack_from('<I',original,oldmap)[0];entries=[struct.unpack_from('<HHII',original,oldmap+4+12*i) for i in range(n)];code=[x[3] for x in entries if x[0]==0x2001];assert len(code)==1 and struct.unpack_from('<I',original,code[0]+12)[0]==7 and struct.unpack_from('<I',original,72)[0]==2;code=code[0];struct.pack_into('<H',original,code,2);nonzero_words=(0x01fe,1,0x01ff,1,0x00fe,0,0x000e);struct.pack_into('<7H',original,code+16,*nonzero_words);assert oldmap+4+12*n==len(original);handles=len(original)+12;struct.pack_into('<I',original,oldmap,n+1);original.extend(struct.pack('<HHII',8,0,2,handles));original.extend(struct.pack('<HHHHHHHH',4,0,0,0,4,0,0,0));struct.pack_into('<I',original,32,len(original));struct.pack_into('<I',original,104,len(original)-struct.unpack_from('<I',original,108)[0]);original[4:7]=b'039';variants['nonzero-039']=original
for name,off,value in [('bad-handle-two',2,2),('bad-type-two',6,2),('bad-register-two',0,0x02fe)]:
 d=bytearray(original);struct.pack_into('<H',d,code+16+off,value);variants[name]=d
result={}
for name,blob in variants.items():
 fix(blob);p=a.out/(name+'.dex')
 with p.open('xb') as f:f.write(blob)
 result[name]={'sha256':hashlib.sha256(blob).hexdigest(),'bytes':len(blob)}
(a.out/'expected.json').write_text(json.dumps({'fixtures':result,'source_sha256':hashlib.sha256(base).hexdigest(),'code_offset':416,'words':list(words),'nonzero_code_offset':code,'nonzero_words':list(nonzero_words),'expected':[[0,0,0,254,0],[2,0,0,255,1],[4,0,0,254,0]],'scope':'authored mutated DEX structure, not ART legality or runtime target'},indent=2)+'\n');print('PASS fixtures',len(variants))
