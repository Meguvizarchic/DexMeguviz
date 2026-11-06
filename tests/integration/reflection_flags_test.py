"""Static v13 flag projection, Unknown handling, version identity and fixed DEX controls."""
import argparse, hashlib, json, struct, subprocess, sys, tempfile
from pathlib import Path

p=argparse.ArgumentParser()
for name in ('exe','fixture','generator'):p.add_argument('--'+name,required=True,type=Path)
a=p.parse_args()
fixture_hash='e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a'
assert hashlib.sha256(a.fixture.read_bytes()).hexdigest()==fixture_hash
u32=lambda n:struct.pack('<I',n)
u64=lambda n:struct.pack('<Q',n)
canonical=(b'DexMeguviz:QueryIR:reflection-flags-v13'+b''.join(u32(n) for n in (1,0,100))+u64(100000000)
           +b''.join(u32(n) for n in (8,0,0,2097410,0,0))+b''.join(u32(n) for n in (11,0,2,1,0xffffffff,0)))
assert len(canonical)==107 and hashlib.sha256(canonical).hexdigest()=='ce19346558f2181fb0343892caf45f566a02cf026f92496e43ff507a78b02e88'
golden='query:v13:'+hashlib.sha256(canonical).hexdigest()
flag=lambda mode,value:{'flags':{'mode':mode,'value':value,'domain':'reflection'}}
owner=lambda mode,value:{'owner_flags':{'mode':mode,'value':value,'domain':'reflection'}}
records=[]
with tempfile.TemporaryDirectory(prefix='dmg-reflection-flags-') as tmp:
    root=Path(tmp)
    def call(name,relation,where,source=None,cap=True,intent='enumerate',extra=None,expected=0,sources=(),incomplete=False):
        data={'schema_version':1,'relation':relation,'where':where,'intent':intent,'max_results':100}
        if cap:data['required_capabilities']=['reflection_flags_static']
        if extra:data['required_capabilities'].extend(extra)
        path=root/(name+'.json');path.write_text(json.dumps(data,ensure_ascii=True),encoding='utf-8')
        command=[str(a.exe.resolve()),'query',str((source or a.fixture).resolve()),'--query',str(path),'--json']
        for more in sources:command+=['--source',str(more.resolve())]
        if incomplete:command+=['--scope-incomplete']
        result=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',timeout=30)
        assert result.returncode==expected,(name,result.returncode,result.stdout,result.stderr)
        value=json.loads(result.stdout);records.append(name)
        return value
    def names(v):return [row.get('name') for row in v['candidates']]
    classes=call('classes','class_defs',flag('contains',1))
    assert classes['query_id']==golden and classes['profile']=='dex-query-reflection-flags-v13'
    assert classes['execution_status']=='Complete' and classes['coverage']=='Partial' and classes['unknown_rows']==1
    assert {row['type_descriptor'] for row in classes['candidates']}=={'Ljava/lang/Object;','Lcatalog/InterfaceA;','Lcatalog/InterfaceB;','Lcatalog/Child;'}
    annotated=call('class-annotated','class_defs',{'all':[{'descriptor':'Lcatalog/Base;'},flag('contains',1)]},intent='unique')
    assert (annotated['coverage'],annotated['decision'],annotated['reason'],annotated['unknown_rows'])==('Partial','Undetermined','UnknownAttribute',1)
    fields=call('fields','field_defs',flag('contains',1))
    assert fields['coverage']=='Complete' and fields['unknown_rows']==0 and len(fields['candidates'])==3
    field_exact=call('field-exact','field_refs',flag('exact',9))
    assert [(x['name'],x['access_flags']) for x in field_exact['candidates']]==[('shared',9)] and field_exact['unknown_rows']==1
    duplicate=call('two-occurrences','field_defs',flag('exact',9),intent='unique',sources=(a.fixture,))
    assert (duplicate['decision'],duplicate['reason'])==('ProvenFalse','Ambiguous')
    assert [x['source_index'] for x in duplicate['candidates']]==[0,1]
    assert duplicate['sources'][0]['content_id']==duplicate['sources'][1]['content_id']
    assert duplicate['sources'][0]['occurrence_id']!=duplicate['sources'][1]['occurrence_id']
    incomplete=call('scope-incomplete','field_defs',flag('exact',9),intent='unique',incomplete=True)
    assert (incomplete['coverage'],incomplete['decision'],incomplete['reason'])==('Partial','Undetermined','SourceScopeIncomplete')
    owner_true=call('owner-true','field_refs',owner('contains',1))
    assert [(x['owner'],x['name']) for x in owner_true['candidates']]==[('Lcatalog/Child;','shared')]
    assert owner_true['coverage']=='Partial' and owner_true['unknown_rows']==3
    missing=call('missing','field_refs',{'all':[{'name':'externalField'},flag('contains',1)]},intent='unique')
    assert (missing['coverage'],missing['decision'],missing['reason'],missing['unknown_rows'])==('Partial','Undetermined','UnknownAttribute',1)
    for label,predicate in [('contains-zero',flag('contains',0)),('any-zero',flag('any',0)),('exact-zero',flag('exact',0)),('not-flags',{'not':flag('contains',1)}),
                            ('owner-zero',owner('contains',0)),('not-owner',{'not':owner('contains',1)})]:
        result=call(label,'field_refs',{'all':[{'name':'externalField'},predicate]},intent='unique')
        assert (result['coverage'],result['decision'],result['reason'],result['unknown_rows'])==('Partial','Undetermined','UnknownAttribute',1),label
    false_unknown=call('false-and-unknown','field_refs',{'all':[{'name':'missing'},flag('contains',1)]},intent='unique')
    assert (false_unknown['coverage'],false_unknown['decision'],false_unknown['unknown_rows'])==('Complete','ProvenFalse',0)
    true_unknown=call('true-or-unknown','field_refs',{'all':[{'name':'externalField'},{'any':[True,flag('contains',1)]}]})
    assert true_unknown['coverage']=='Complete' and names(true_unknown)==['externalField']
    methods=call('method-abstract','method_defs',flag('exact',0x401))
    assert names(methods)==['abstractMethod'] and methods['coverage']=='Complete'
    no_cap=call('no-cap','method_defs',flag('contains',1),cap=False,expected=2)
    assert no_cap['execution_status']=='Unsupported'
    advanced=call('advanced','method_defs',flag('contains',1),extra=['numeric_literals'],expected=2)
    assert advanced['execution_status']=='Unsupported'
    plain=call('raw','method_defs',{'flags':{'mode':'contains','value':1,'domain':'dex'}},cap=False)
    short=call('raw-short','method_defs',{'flags_contains':1},cap=False)
    assert plain['query_id']==short['query_id'] and plain['query_id'].startswith('query:v1:')
    graph=call('graph',{'op':'scan','relation':'field_refs','where':flag('exact',9)},True,expected=2)
    assert graph['execution_status']=='Unsupported'
    # Vary native declaration bits in the project-original generator. Native
    # has no code item; rebuilding updates all offsets, SHA-1 and Adler-32.
    script=a.generator.read_text(encoding='utf-8');old='uleb(0x401)';assert script.count(old)==1
    for label,raw,should_match in [('native-sync',0x121,False),('declared-sync',0x20121,True)]:
        changed=root/(label+'.py');changed.write_text(script.replace(old,'uleb('+str(raw)+')'),encoding='utf-8')
        out=root/(label+'-fixture');run=subprocess.run([sys.executable,str(changed),'--output',str(out)],capture_output=True,timeout=30)
        assert run.returncode==0,(label,run.stderr)
        result=call(label,'method_defs',flag('contains',0x20),source=out/'definitions.dex')
        assert names(result)==(['abstractMethod'] if should_match else []) and result['coverage']=='Complete'
        raw_result=call(label+'-raw','method_defs',{'flags_contains':0x20},source=out/'definitions.dex',cap=False)
        assert names(raw_result)==['abstractMethod']
    # Hidden-API-style method/field low bits cannot become certain metadata.
    changed=root/'hidden-native.py';changed.write_text(script.replace(old,'uleb(769)'),encoding='utf-8') # native | 0x200 | public
    out=root/'hidden-native-fixture';run=subprocess.run([sys.executable,str(changed),'--output',str(out)],capture_output=True,timeout=30)
    assert run.returncode==0,run.stderr
    native_unknown=call('hidden-native','method_defs',flag('contains',1),source=out/'definitions.dex',intent='unique')
    assert (native_unknown['coverage'],native_unknown['decision'],native_unknown['reason'],native_unknown['query_profile']['unknown_rows'])==('Partial','Undetermined','UnknownAttribute',1)
    field_old='("instanceField", 1)';assert script.count(field_old)==1
    changed=root/'hidden-field.py';changed.write_text(script.replace(field_old,'("instanceField", 33)'),encoding='utf-8')
    out=root/'hidden-field-fixture';run=subprocess.run([sys.executable,str(changed),'--output',str(out)],capture_output=True,timeout=30)
    assert run.returncode==0,run.stderr
    hidden=call('hidden-field','field_defs',{'all':[{'name':'instanceField'},flag('contains',1)]},source=out/'definitions.dex',intent='unique')
    assert (hidden['coverage'],hidden['decision'],hidden['reason'],hidden['unknown_rows'])==('Partial','Undetermined','UnknownAttribute',1)
    raw_hidden=call('hidden-field-raw','field_defs',{'flags_exact':33},source=out/'definitions.dex',cap=False)
    assert names(raw_hidden)==['instanceField']
print('PASS',len(records),'static reflection flags query checks; no ART/loader equivalence claim')
