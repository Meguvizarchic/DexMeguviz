"""Generate the fixed empty-string DEX fixture using the project DEX generator."""
import argparse,hashlib,importlib.util,json
from pathlib import Path

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--generator",type=Path,required=True);parser.add_argument("--out",type=Path,required=True);a=parser.parse_args()
    spec=importlib.util.spec_from_file_location("fixture_generator",a.generator);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.TEXT=""
    data,metadata=module.build_dex("035")
    if metadata["unicode_string_utf16"]!=[]:raise ValueError("fixture mismatch")
    a.out.mkdir(parents=True,exist_ok=False);(a.out/"empty.dex").write_bytes(data)
    provenance={"generator":"tests/fixtures/generators/generate_dex.py","generator_sha256":hashlib.sha256(a.generator.read_bytes()).hexdigest(),"fixture_sha256":hashlib.sha256(data).hexdigest(),"case":"empty DEX string at string_id 0"}
    (a.out/"provenance.json").write_text(json.dumps(provenance,indent=2)+"\n")
if __name__=="__main__":main()
