"""Create a deterministic over-limit graph text fixture from the fixed DEX generator."""
import argparse,ast,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--generator',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
source=a.generator.read_bytes();assert hashlib.sha256(source).hexdigest()=='fe20d2e471999897bcadee7b70438636397d16cd0e2b4c11b39d3fe041353ddc'
class Change(ast.NodeTransformer):
    count=0
    def visit_Constant(self,node):
        if node.value=='Example.java':
            self.count+=1;return ast.copy_location(ast.Constant(value='A'*600000),node)
        return node
tree=ast.parse(source.decode('utf-8'));change=Change();tree=change.visit(tree);assert change.count==2
ns={'__name__':'graph_large_fixture','__file__':str(a.generator)};exec(compile(ast.fix_missing_locations(tree),str(a.generator),'exec'),ns)
data,_=ns['build_dex']('035');a.out.mkdir(parents=True,exist_ok=False);(a.out/'large.dex').write_bytes(data)
(a.out/'manifest.json').write_text(json.dumps({'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'units':600000},indent=2)+'\n')
print('PASS generated large graph fixture',hashlib.sha256(data).hexdigest())

