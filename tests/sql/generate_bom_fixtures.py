"""Generate two test-only DEX fixtures from the pinned original generator."""
import argparse, ast, hashlib, json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--generator',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
source=a.generator.read_bytes()
assert hashlib.sha256(source).hexdigest()=='fe20d2e471999897bcadee7b70438636397d16cd0e2b4c11b39d3fe041353ddc'
a.out.mkdir(parents=True,exist_ok=False)
records={}
for name,value in [('feff','\ufeffleading'),('fffe','\ufffeleading'),('high','\ud800leading'),('low','\udfffleading'),('endnul','tail\0'),('long','x'*2048)]:
    class Change(ast.NodeTransformer):
        count=0
        def visit_Constant(self,node):
            if node.value=='Example.java':
                self.count+=1
                return ast.copy_location(ast.Constant(value=value),node)
            return node
    tree=ast.parse(source.decode('utf-8'),filename=str(a.generator));change=Change();tree=change.visit(tree);assert change.count==2
    namespace={'__name__':'sql_bom_fixture','__file__':str(a.generator)}
    exec(compile(ast.fix_missing_locations(tree),str(a.generator),'exec'),namespace)
    data,_=namespace['build_dex']('035');(a.out/(name+'.dex')).write_bytes(data)
    records[name]={'sha256':hashlib.sha256(data).hexdigest(),'target_utf16':[ord(c) for c in value]}
(a.out/'manifest.json').write_text(json.dumps(records,indent=2)+'\n')
print('PASS generated FEFF/FFFE DEX fixtures')
