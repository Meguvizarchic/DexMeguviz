"""Self-built true 041 headers, absolute offsets and later shared string data."""
from pathlib import Path
import hashlib,json,struct,zlib,argparse

def main(out):
    out.mkdir(parents=True,exist_ok=False)
    b=bytearray(448)
    def put(at,*words):struct.pack_into('<'+'I'*len(words),b,at,*words)
    def leb(n):
        a=bytearray()
        while n>=128:a.append((n&127)|128);n>>=7
        a.append(n);return bytes(a)
    strings=['LA;','LB;','V','alpha','beta','hello'];offsets=[]
    for text in strings:offsets.append(len(b));b+=leb(len(text))+text.encode()+b'\0'
    while len(b)%4:b.append(0)
    maps=[]
    for index in range(2):
        h=index*120;type_off=264+8*index;proto_off=280+12*index;method_off=304+8*index;class_off=320+32*index;code_off=384+24*index;data_off=432+8*index
        entries=sorted([(0,1,h),(1,6,240),(2,2,type_off),(3,1,proto_off),(5,1,method_off),(6,1,class_off),(0x2001,1,code_off),(0x2000,1,data_off),(0x2002,6,448),(0x1000,1,len(b))],key=lambda v:v[2])
        maps.append(len(b));b+=struct.pack('<I',len(entries))
        for kind,count,at in entries:b+=struct.pack('<HHII',kind,0,count,at)
    put(240,*offsets)
    for index in range(2):
        h=index*120;put(264+8*index,index,2);put(280+12*index,2,1,0);struct.pack_into('<HHI',b,304+8*index,0,0,3+index)
        put(320+32*index,0,1,0xffffffff,0,0xffffffff,0,432+8*index,0)
        struct.pack_into('<HHHHIIHHH',b,384+24*index,1,0,0,0,0,3,0x001a,5,0x000e)
        b[432+8*index:440+8*index]=bytes([0,0,1,0,0,9])+leb(384+24*index)
        b[h:h+8]=b'dex\n041\0';put(h+32,120 if index==0 else len(b)-120,120,0x12345678,0,0,maps[index],6,240,2,264+8*index,1,280+12*index,0,0,1,304+8*index,1,320+32*index,0,0,len(b),h)
    # Official checksum uses Begin()/Size(): the logical extent, not shared tail.
    for h in [120,0]:
        n=struct.unpack_from('<I',b,h+32)[0];b[h+12:h+32]=hashlib.sha1(b[h+32:h+n]).digest();put(h+8,zlib.adler32(b[h+12:h+n])&0xffffffff)
    (out/'shared-strings.dex').write_bytes(b)
    (out/'query.json').write_text(json.dumps({'schema_version':1,'relation':'method_defs','where':{'using_strings':{'all':[{'op':'exact','value':'hello'}]}},'intent':'enumerate','max_results':10}))
    (out/'manifest.json').write_text(json.dumps({'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'headers':[0,120],'methods':[['LA;','alpha'],['LB;','beta']],'shared_string_ids':240,'shared_string_data':448,'scope':'constructed metadata/instruction fixture; not ART verified'},indent=2))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);main(p.parse_args().out)
