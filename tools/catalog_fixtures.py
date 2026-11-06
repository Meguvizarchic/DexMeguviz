"""Build a deterministic corpus catalog; private APKs are references, never copied."""
from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parents[1];fixtures=root/'tests/fixtures'
suites=[
 ('base','generators/generate_dex.py',['generated/*.dex','malformed/*.dex'],['expected.json','manifest.json'],'035/037/038/039/040, UTF16/NUL/surrogates, external references, metadata corruption'),
 ('unicode','generators/generate_unicode.py',['generated/unicode/*.dex'],['generated/unicode/expected.json'],'lone UTF-16 surrogates, embedded NUL, and supplementary pairs'),
 ('graph','generators/generate_graph_dex.py',['generated/graph/*.dex'],['generated/graph/manifest.json'],'static multi-source method identities and independently authored call graph samples'),
 ('q03','generators/generate_q03.py',['generated/q03/*.dex'],['generated/q03/expected.json'],'annotation, static-value and method-use string evidence domains'),
 ('q04','generators/generate_q04.py',['generated/q04/*.dex'],['generated/q04/manifest.json'],'multi-method string-use sets, scope and occurrence identity'),
 ('q06','generators/generate_q06.py',['generated/q06/*.dex'],['generated/q06/manifest.json'],'same target at distinct call sites, overloads and external references'),
 ('q08','generators/generate_q08.py',['generated/q08/*.dex'],['generated/q08/manifest.json'],'own declarations, direct parent and method field read/write domains'),
 ('numeric','generators/numeric_facts.py',['generated/numeric/*.dex'],['generated/numeric/expected.json'],'const and arithmetic literal events; checked static code item only'),
 ('q09-stream','generators/generate_q09_stream.py',['generated/q09-stream/*.dex'],['generated/q09-stream/expected.json'],'unresolved field before defined fields; checked streaming and resource cases'),
 ('inherited-edges-v2','generators/generate_inherited_edges.py',['generated/inherited-edges-v2/*.dex'],['generated/inherited-edges-v2/manifest.json'],'private same-name hiding, same-name distinct types, and interface Unknown'),
 ('inherited','generators/generate_inherited.py',['generated/inherited/*.dex'],['generated/inherited/manifest.json'],'cross-source superclass field observations with ambiguity and partial scope'),
 ('inherited-use','generators/generate_inherited_use.py',['generated/inherited-use/*.dex'],['generated/inherited-use/expected.json'],'inherited superclass proofs joined to same-source callsites and target references'),
 ('interface-v8','generators/generate_interface_v8.py',['generated/interface-v8-v4/*.dex'],['generated/interface-v8-v4/manifest.json'],'static superclass and interface fields; diamonds, hiding, ambiguity and unsupported flags'),
 ('interface-use','generators/generate_interface_use.py',['generated/interface-use/*.dex'],['generated/interface-use/expected.json'],'interface inheritance and source-local static invoke evidence'),
 ('interface-v11','generators/generate_interface_v11.py',['generated/interface-v11/*.dex'],['generated/interface-v11/manifest.json'],'static interface roots and multiple definition branches; scoped evidence only'),
 ('composite-v10','generators/composite_v10.py',['generated/composite-v10/*.dex'],['generated/composite-v10/manifest.json'],'static superclass, numeric literal and invocation composition'),
 ('cross-capability-v10','generators/generate_cross_v10.py',['generated/cross-capability-v10/*.dex'],['generated/cross-capability-v10/manifest.json'],'static interface edge, numeric literal and caller invocation across sources'),
 ('q10','generators/generate_q10.py',['generated/q10/*.dex'],['generated/q10/expected.json'],'33 static method definitions and test-only post-validation model'),
 ('q11','generators/generate_q11.py',['generated/q11/*.dex'],['generated/q11/manifest.json'],'global TopN, multi-source stable ties and scope'),
 ('extended','generators/metadata_extended.py',['generated/extended/*.dex'],['generated/extended/manifest.json'],'shared items, SLEB, type lists, code metadata and topology'),
 ('facts','generators/facts_cases.py',['generated/method_facts/*.dex'],['generated/method_facts/expected.json','generated/method_facts/invoke-domains-038.expected.json'],'PC/domain golden values, no-body and pool-only values; 038 fixture is structural only'),
 ('use-relations','generators/use_relations.py',['generated/use_relations/*.dex'],['generated/use_relations/expected.json'],'multiple PCs per target, field reads/writes, jumbo strings, valid facts before a corrupt opcode'),
 ('unique-one-v12','generators/unique_one_utf16.py',['generated/unique-one-v12/*.dex'],['generated/unique-one-v12/manifest.json'],'v12 string-use fixture referencing UTF-16 supplementary pair'),
 ('use-stream-v9','generators/use_stream_v9.py',['generated/use-stream-v9/*.dex'],['generated/use-stream-v9/manifest.json'],'two checked methods, later corruption and incremental use evidence'),
 ('definitions','generators/definition_catalog.py',['generated/definition_catalog/*.dex'],['generated/definition_catalog/expected.json'],'class/field definitions, external field refs, interface order'),
 ('archive','generators/archive_fixtures.py',['generated/archive/*.apk','generated/archive/*.zip'],['generated/archive/manifest.json'],'stored/deflate/ZIP64/CRC/zipalign, limits and cancellation'),
 ('multisource','generators/multisource_fixtures.py',['generated/multisource/*.apk','generated/multisource/*.dex'],['generated/multisource/manifest.json'],'ordered occurrences, repeated bytes, incomplete scope, atomic failures'),
 ('array-data-facts','generators/array_data_facts.py',['generated/array-data-facts/*.dex'],['generated/array-data-facts/expected.json'],'referenced fill-array-data payload bits, original single-method DEX'),
 ('switch-facts','generators/switch_facts.py',['generated/switch-facts/*.dex'],['generated/switch-facts/expected.json'],'packed and sparse signed switch keys, payloads and local targets'),
 ('dataflow-v1','generators/dataflow_v1.py',['generated/dataflow-v1/*.dex'],['generated/dataflow-v1/expected.json'],'structural int32 constant join and reaching definition'),
 ('dataflow-invoke-v1','generators/dataflow_invoke_v1.py',['generated/dataflow-invoke-v1/*.dex'],['generated/dataflow-invoke-v1/expected.json'],'opaque invoke argument words and unknown result'),
 ('branch-facts','generators/branch_facts.py',['generated/branch-facts/*.dex'],['generated/branch-facts/expected.json'],'checked encoded goto/if destination PCs, not runtime reachability'),
 ('jni-utf16','generators/generate_jni_utf16.py',['generated/jni-utf16/*.dex'],['generated/jni-utf16/expected.json'],'legal supplementary DEX names and JNI UTF-16 query cases'),
 ('query-ir','generators/query_ir_cases.py',['generated/query-ir/*.dex'],['generated/query-ir/expected.json'],'late-shard global TopN winner; source occurrence retained'),
 ('annotations-general','annotations-general/generate.py',['annotations-general/*.dex'],['annotations-general/expected.json'],'class, field, method and parameter annotations with nested encoded values'),
 ('symbol-text-v1','symbol-text-v1/generate.py',['symbol-text-v1/*.dex'],['symbol-text-v1/provenance.json'],'empty source-local UTF-16 string')]
catalog=[]
for name,generator,patterns,oracles,scope in suites:
 files=sorted(set(p for pattern in patterns for p in fixtures.glob(pattern)))
 assert files and (fixtures/generator).is_file(),name
 oracle_records={p:hashlib.sha256((fixtures/p).read_bytes()).hexdigest() for p in oracles if (fixtures/p).is_file()}
 assert oracle_records,name
 catalog.append({'id':name,'generator':generator,'generator_sha256':hashlib.sha256((fixtures/generator).read_bytes()).hexdigest(),'scope':scope,'license':'Project-original; distribution license pending owner decision','oracle':'Authored semantic model and independent byte readers; never native first-run golden','oracle_files':oracle_records,'files':[{'path':p.relative_to(fixtures).as_posix(),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]})
result={'schema_version':1,'suites':catalog,'instruction_cases':'tests/native/decoder_tests.cpp; independently pinned opcode widths in generated/instructions/opcode_widths.json','real_APKs':'docs/evidence/local-corpus-inventory.json; binaries are not included or uploaded','remaining_coverage':['Full QueryIR Q04/Q07/Q08/Q10/Q11/Q12 and project profiles','SQL S01-S11','persistent cache F12','Android ClassLoader, 4KiB/16KiB and runtime verification','device/foreground A/B/C baselines'],'task_state_authority':'backlog.json'}
(fixtures/'catalog.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'suites':len(catalog),'fixture_records':sum(len(s['files']) for s in catalog),'private_APK_copies':0}))
