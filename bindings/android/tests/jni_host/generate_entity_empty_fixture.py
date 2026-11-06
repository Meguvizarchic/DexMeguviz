"""Derive an original metadata DEX with an empty string and a NUL string.

The project's fixed generator is transformed only at its two source-file-name
constants. This keeps the authored structure while making the first sorted
string empty; the generated DEX is not an ART verifier claim.
"""
import argparse,ast,hashlib,json
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument('--generator',type=Path,required=True)
parser.add_argument('--out',type=Path,required=True)
args=parser.parse_args()
source=args.generator.read_bytes()
assert hashlib.sha256(source).hexdigest()=='fe20d2e471999897bcadee7b70438636397d16cd0e2b4c11b39d3fe041353ddc'
class Change(ast.NodeTransformer):
    count=0
    def visit_Constant(self,node):
        if node.value=='Example.java':
            self.count+=1
            return ast.copy_location(ast.Constant(value=''),node)
        return node
tree=ast.parse(source.decode('utf-8'),filename=str(args.generator));change=Change();tree=change.visit(tree);assert change.count==2
namespace={'__name__':'entity_empty_fixture','__file__':str(args.generator)}
exec(compile(ast.fix_missing_locations(tree),str(args.generator),'exec'),namespace)
data,expected=namespace['build_dex']('035')
assert expected['unicode_string_utf16']==[38634,55357,56832,0,116,97,105,108]
args.out.mkdir(parents=True,exist_ok=False)
(args.out/'empty-nul.dex').write_bytes(data)
(args.out/'manifest.json').write_text(json.dumps({'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),
    'generator_sha256':hashlib.sha256(source).hexdigest(),'empty_string':'',
    'nul_utf16':expected['unicode_string_utf16'],'scope':'authored metadata; no ART claim'},indent=2)+'\n',encoding='utf-8')
print('PASS generated empty and NUL string fixture')
