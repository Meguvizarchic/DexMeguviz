"""Independent raw-DEX and authored Join/SemiJoin CLI acceptance cases."""
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field
import argparse, copy, hashlib, json, struct, subprocess, sys, time, zlib

sys.dont_write_bytecode = True


@dataclass
class Row:
    entity: tuple
    bindings: frozenset = frozenset()
    links: tuple = ()
    proofs: frozenset = frozenset()
    certain: bool = True


def binding(label, entity, *path):
    return (label, entity, tuple(path))


def identity(row, mode='tuple'):
    return row.entity if mode == 'entity' else (row.entity, row.bindings)


def distinct(rows, mode='tuple'):
    result, seen = [], {}
    for row in rows:
        key = identity(row, mode)
        if key not in seen:
            seen[key] = len(result); result.append(row)
        elif row.certain and not result[seen[key]].certain:
            result[seen[key]] = row
    return result


def scan(relation, where=None, slot=None):
    value = {'op':'scan','relation':relation}
    if where is not None:value['where']=where
    if slot is not None:value['scope']={'slots':[slot]}
    return value


def label(value, name):return {'op':'label','input':value,'label':name}
def union(*values, semantics='bag'):return {'op':'union','semantics':semantics,'inputs':list(values)}
def join(left,right,key='same_entity',op='join'):return {'op':op,'left':left,'right':right,'on':key}
def distinct_op(value):return {'op':'distinct','input':value,'identity':'tuple'}


def paired(left, right, key, node=0):
    links = (*left.links,*right.links,(node,key,left.entity,right.entity))
    bindings = {binding(None,left.entity,'L'),binding(None,right.entity,'R')}
    bindings.update((role,entity,('L',*path)) for role,entity,path in left.bindings)
    bindings.update((role,entity,('R',*path)) for role,entity,path in right.bindings)
    return Row(left.entity,frozenset(bindings),links,certain=left.certain and right.certain)


def semi(left, right, key, node=0):
    proofs={(node,None,right.entity,('R',))}
    proofs.update((node,role,entity,('R',*path)) for role,entity,path in right.bindings)
    return Row(left.entity,left.bindings,(*left.links,*right.links,(node,key,left.entity,right.entity)),frozenset(proofs),left.certain and right.certain)


def raw_key(item):return (item['relation'],item['source_index'],item['local_index'])


def expected_signature(row):
    return (row.entity,row.bindings,tuple(sorted(row.links)),row.proofs)


def golden_join_query_id(key):
    """Independent canonical bytes for default join(method_defs scan, same scan)."""
    key_value={'same_entity':0,'symbol':3}[key]
    u32=lambda n:struct.pack('<I',n)
    u64=lambda n:struct.pack('<Q',n)
    frame=lambda b:u64(len(b))+b
    predicate=b''.join(u32(n) for n in (0,0,0,0,0xffffffff,0))
    scan_node=b''.join(u32(n) for n in (0,0,1))+frame(predicate)
    scan_node+=b''.join(u32(n) for n in (0,1,0xffffffff,1,0,0,0,0,0,0))
    top=b''.join(u32(n) for n in (0,0,4096))+u64(100000000)
    top+=b''.join(u32(n) for n in (7,1,0,2563,0,100000,0,0))
    join_node=b''.join(u32(n) for n in (6,0,0,0,1,0xffffffff,1,0,0,0,key_value,0,0,2))
    canonical=b'DexMeguviz:QueryIR:relational-v3'+top+join_node+frame(scan_node)+frame(scan_node)
    assert len(canonical)==324
    return 'query:v3:'+hashlib.sha256(canonical).hexdigest()


def run(exe, root):
    sys.path.insert(0,str(root/'tests/integration'))
    sys.path.insert(0,str(root/'tools/evidence_verifier'))
    from relational_test import Oracle
    from entity_query_test import raw_entities
    from multisource import verify_metadata
    source=root/'tests/fixtures/generated/definition_catalog/definitions.dex'
    method_source=root/'tests/fixtures/generated/method_facts/method-uses.dex'
    out=root/'docs/evidence/join-query'/('run-'+str(time.time_ns()));out.mkdir(parents=True)
    exe_sha=hashlib.sha256(exe.read_bytes()).hexdigest();records=[];rejected=[]
    one=Oracle(root,[source]);two=Oracle(root,[source,source]);mixed=Oracle(root,[source,method_source])

    def check(value, oracle, expected, *, relation=None, unknown=0, complete=True, decision='NotApplicable',reason=None,
              identity_mode='entity', identity_count=None, execution='Complete', scan_total=None, max_results=None):
        assert value['profile']=='dex-query-relational-v3'
        if relation is not None:assert value['relation']==relation
        assert value['counter_domain']=='scan_records' and value['execution_status']==execution
        assert value['coverage']==('Complete' if complete else 'Partial') and value['decision']==decision
        assert value['reason']==(reason if reason is not None else ('UnknownAttribute' if unknown else 'None'))
        assert value['unknown_rows']==unknown
        assert value['query_scope']['complete'] is oracle.dataset['scope_complete'] or complete or unknown
        metadata=dict(value);metadata['profile']='dex-query-method-v1';verify_metadata(oracle.dataset,metadata)
        assert value['query_id'].startswith('query:v3:')
        graph=value['relation_profile'];assert graph['unique_by']==identity_mode
        if identity_count is not None:assert graph['identity_count']==identity_count
        operators=graph['operators'];ids={v['node_id']:v for v in operators}
        assert len(ids)==len(operators) and graph['root_node'] in ids
        visits=sum(v['visited_rows'] for v in operators if v['op']=='scan')
        totals=sum(v['total_rows'] for v in operators if v['op']=='scan')
        assert value['visited_rows']==visits and value['total_rows']==totals
        if scan_total is not None:assert visits==totals==scan_total
        candidates=value['candidates'];assert len(candidates)==len(expected)
        signatures=[]
        for row in candidates:
            entity=raw_key(row);assert entity in oracle.entities;oracle.check_entity(row,entity)
            bindings=[]
            for item in row['bindings']:
                key=raw_key(item);assert key in oracle.entities;oracle.check_entity(item,key,True)
                path=tuple(item.get('path',[]));assert all(x in ('L','R') for x in path)
                bindings.append((item['label'],key,path))
            assert len(bindings)==len(set(bindings))
            links=[]
            for link in row.get('links',[]):
                left,right=raw_key(link['left']),raw_key(link['right']);node=link['operator_node']
                assert left in oracle.entities and right in oracle.entities and node in ids
                assert ids[node]['op'] in ('join','semi_join')
                key=link['key'];a,b=oracle.entities[left],oracle.entities[right]
                if key=='same_entity':assert left==right
                elif key=='local_definition':
                    assert left[1]==right[1] and a['reference_index']==b['reference_index']
                    assert a['has_local_definition'] and b['has_local_definition']
                elif key=='local_owner':assert left[1]==right[1] and a['owner']==b['type_descriptor']
                elif key=='symbol':
                    assert all(a.get(k)==b.get(k) for k in ('owner','name','prototype','type_descriptor','string_value'))
                else:raise AssertionError('unknown link key')
                links.append((node,key,left,right))
            proofs=[]
            for proof in row.get('proof_bindings',[]):
                key=raw_key(proof['entity']);assert key in oracle.entities;oracle.check_entity(proof['entity'],key,True)
                node=proof['operator_node'];assert node in ids and ids[node]['op']=='semi_join'
                path=tuple(proof['path']);assert path and path[0]=='R' and all(x in ('L','R') for x in path)
                proofs.append((node,proof['label'],key,path))
            assert len(proofs)==len(set(proofs))
            evidence_entities={entity,*(b[1] for b in bindings),*(p[2] for p in proofs)}
            assert row['evidence']
            for witness in row['evidence']:
                assert witness['operator_node'] in ids and raw_key(witness['entity']) in evidence_entities
                assert type(witness['matched']) is bool
            signatures.append((entity,frozenset(bindings),tuple(sorted(links)),frozenset(proofs)))
        assert Counter(signatures)==Counter(expected_signature(r) for r in expected),(signatures,expected)
        if max_results is not None:assert len(candidates)<=max_results
        return value

    def call(name, oracle, relation, expected=None, *, code=0, scope_incomplete=False, allow_partial=False, **options):
        query={'schema_version':1,'relation':relation,'max_results':100,**options}
        path=out/(name+'.query.json');path.write_text(json.dumps(query,ensure_ascii=True,indent=2),encoding='utf-8')
        command=[str(exe),'query',str(oracle.paths[0]),'--query',str(path),'--json']
        for extra in oracle.paths[1:]:command+=['--source',str(extra)]
        if scope_incomplete:command.append('--scope-incomplete')
        p=subprocess.run(command,capture_output=True,timeout=30)
        (out/(name+'.stdout.json')).write_bytes(p.stdout);(out/(name+'.stderr.log')).write_bytes(p.stderr)
        records.append({'name':name,'command':command,'exit_code':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest()})
        (out/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
        assert p.returncode==code,(name,p.returncode,p.stdout,p.stderr)
        value=json.loads(p.stdout)
        if code and not allow_partial:
            assert value['coverage']=='Partial' and value['decision']=='Undetermined' and not value['candidates']
        elif expected is not None:
            check(value,oracle,expected,**options.get('_checks',{}))
        return value

    def run_case(name,oracle,expression,expected,*,code=0,incomplete=False,allow_partial=False,check_options=None,**options):
        value=call(name,oracle,expression,None,code=code,scope_incomplete=incomplete,allow_partial=allow_partial,**options)
        if code==0 or allow_partial:check(value,oracle,expected,**(check_options or {}))
        return value

    def reject(name,valid,oracle,expected,mutate,**checks):
        forged=copy.deepcopy(valid);mutate(forged)
        try:check(forged,oracle,expected,**checks)
        except (AssertionError,KeyError,ValueError,TypeError):rejected.append(name)
        else:raise AssertionError('forged evidence accepted: '+name)

    method_key=('method_defs',0,0);method=scan('method_defs',{'name':'abstractMethod'})
    labeled=label(method,'x');choices=union(labeled,method)
    rows=[Row(method_key,frozenset({binding('x',method_key)})),Row(method_key)]
    pairs=[paired(a,b,'same_entity') for a in rows for b in rows]
    pair_query=join(choices,choices)
    result=run_case('four-pair-bag',one,pair_query,pairs,check_options={'relation':'method_defs','identity_count':1,'scan_total':4})
    reject('removed-pair',result,one,pairs,lambda v:v['candidates'].pop(),relation='method_defs',identity_count=1,scan_total=4)
    reject('removed-pair-with-partial',result,one,pairs,lambda v:(v['candidates'].pop(),v.update(coverage='Partial')),relation='method_defs',identity_count=1,scan_total=4)
    reject('wrong-right-endpoint',result,one,pairs,lambda v:v['candidates'][0]['links'][0]['right'].update(local_index=1),relation='method_defs',identity_count=1,scan_total=4)
    reject('inverted-binding-side',result,one,pairs,lambda v:v['candidates'][0]['bindings'][0].update(path=['R']),relation='method_defs',identity_count=1,scan_total=4)
    result=run_case('four-distinct-tuples',one,distinct_op(pair_query),[paired(a,b,'same_entity',1) for a in rows for b in rows],
                    check_options={'relation':'method_defs','identity_mode':'tuple','identity_count':4,'scan_total':4},unique_by='tuple')
    assert len(result['candidates'])==4
    run_case('tuple-unique',one,pair_query,pairs[:2],check_options={'relation':'method_defs','identity_mode':'tuple','identity_count':4,'scan_total':4,'decision':'ProvenFalse','reason':'Ambiguous'},intent='unique',unique_by='tuple')
    run_case('entity-unique',one,pair_query,pairs[:1],check_options={'relation':'method_defs','identity_count':1,'scan_total':4,'decision':'ProvenTrue'},intent='unique')
    twice=union(method,method);thrice=union(method,method,method)
    six=[paired(Row(method_key),Row(method_key),'same_entity') for _ in range(6)]
    run_case('bag-two-times-three',one,join(twice,thrice),six,check_options={'relation':'method_defs','identity_count':1,'scan_total':5})
    run_case('semi-two-not-six',one,join(twice,thrice,op='semi_join'),[semi(Row(method_key),Row(method_key),'same_entity') for _ in range(2)],
             check_options={'relation':'method_defs','identity_count':1,'scan_total':5})
    run_case('root-cap-does-not-cut-join',one,join(twice,thrice),six[:5],code=3,allow_partial=True,max_results=5,
             check_options={'relation':'method_defs','execution':'BudgetExceeded','complete':False,'reason':'ResultLimit','identity_count':1,'scan_total':5})
    simple=join(method,method)
    run_case('different-join-nodes-same-tuple',one,union(simple,simple,semantics='set'),[paired(Row(method_key),Row(method_key),'same_entity',1)],
             unique_by='tuple',check_options={'relation':'method_defs','identity_mode':'tuple','identity_count':1,'scan_total':4})
    inner=paired(Row(method_key),Row(method_key),'same_entity',1)
    nested=[paired(inner,Row(method_key),'same_entity',0)]
    run_case('nested-pair-paths',one,join(simple,method),nested,
             check_options={'relation':'method_defs','identity_count':1,'scan_total':3})

    # ID table and declaration directory are decoded independently from fixture bytes.
    fields=[('field_defs',0,i) for i in range(3)]
    field_refs=[('field_refs',0,one.entities[k]['reference_index']) for k in fields]
    field_pairs=[paired(Row(a),Row(b),'local_definition') for a,b in zip(fields,field_refs)]
    run_case('field-local-definition',one,join(scan('field_defs'),scan('field_refs'),'local_definition'),field_pairs,
             check_options={'relation':'field_defs','identity_count':3,'scan_total':7})
    reverse=[paired(Row(b),Row(a),'local_definition') for b in sorted(field_refs,key=lambda x:x[2]) for a in fields if one.entities[a]['reference_index']==b[2]]
    run_case('reverse-field-local-definition',one,join(scan('field_refs'),scan('field_defs'),'local_definition'),reverse,
             check_options={'relation':'field_refs','identity_count':3,'scan_total':7})
    classes=[('class_defs',0,i) for i in range(5)]
    class_pairs=[paired(Row(c),Row(('type_refs',0,one.entities[c]['reference_index'])),'local_definition') for c in classes]
    run_case('class-type-local-definition',one,join(scan('class_defs'),scan('type_refs'),'local_definition'),class_pairs,
             check_options={'relation':'class_defs','identity_count':5,'scan_total':14})
    owners={one.entities[k]['type_descriptor']:k for k in classes}
    owner_pairs=[paired(Row(f),Row(owners[one.entities[f]['owner']]),'local_owner') for f in fields]
    run_case('field-owner',one,join(scan('field_defs'),scan('class_defs'),'local_owner'),owner_pairs,
             check_options={'relation':'field_defs','identity_count':3,'scan_total':8})
    slot0=two.dataset['inputs'][0]['slot_key'];slot1=two.dataset['inputs'][1]['slot_key']
    run_case('local-owner-cannot-cross-occurrences',two,join(scan('field_defs',slot=slot0),scan('class_defs',slot=slot1),'local_owner'),[],
             check_options={'relation':'field_defs','identity_count':0,'scan_total':8})
    mixed0=mixed.dataset['inputs'][0]['slot_key'];mixed1=mixed.dataset['inputs'][1]['slot_key']
    run_case('local-definition-cannot-cross-sources',mixed,join(scan('method_defs',slot=mixed0),scan('method_refs',slot=mixed1),'local_definition'),[],
             check_options={'relation':'method_defs','identity_count':0,'scan_total':6})
    method_pairs=[paired(Row(('method_defs',a,0)),Row(('method_refs',b,0)),'symbol') for a in range(2) for b in range(2)]
    run_case('symbol-method-cross-source-four',two,join(scan('method_defs'),scan('method_refs'),'symbol'),method_pairs,
             check_options={'relation':'method_defs','identity_count':2,'scan_total':4})
    field_symbols=[paired(Row(a),Row(b),'symbol') for a,b in zip(fields,field_refs)]
    run_case('symbol-full-field-signature',one,join(scan('field_defs'),scan('field_refs'),'symbol'),field_symbols,
             check_options={'relation':'field_defs','identity_count':3,'scan_total':7})
    shared_ids=[k for k,v in two.entities.items() if k[0]=='string_values' and v['string_value']=='shared']
    run_case('symbol-string-cross-source-four',two,join(scan('string_values',{'value':'shared'}),scan('string_values',{'value':'shared'}),'symbol'),
             [paired(Row(a),Row(b),'symbol') for a in shared_ids for b in shared_ids],
             check_options={'relation':'string_values','identity_count':2,'scan_total':52})

    # Right-owner group is proof context for SemiJoin, not a left tuple binding.
    child=('class_defs',0,4);child_field=('field_defs',0,2)
    child_group=Row(child,frozenset({binding(None,child_field),binding('F',child_field),binding(None,method_key),binding('M',method_key)}))
    group={'op':'group_by_owner','inputs':[label(scan('field_defs',{'owner':'Lcatalog/Child;','name':'shared'}),'F'),
           label(method,'M')],'min':2,'max':2,'required_roles':['F','M'],'role_policy':'distinct'}
    group_query=join(method,union(group,group),'local_owner','semi_join')
    group_expected=[semi(Row(method_key),child_group,'local_owner')]
    group_result=run_case('semi-right-role-group-proof',one,group_query,group_expected,unique_by='tuple',
                          check_options={'relation':'method_defs','identity_mode':'tuple','identity_count':1,'scan_total':9})
    reject('semi-delete-proof',group_result,one,group_expected,lambda v:v['candidates'][0]['proof_bindings'].pop(),
           relation='method_defs',identity_mode='tuple',identity_count=1,scan_total=9)
    reject('semi-forged-role',group_result,one,group_expected,
           lambda v:next(p for p in v['candidates'][0]['proof_bindings'] if p['label']=='F').update(label='invented'),
           relation='method_defs',identity_mode='tuple',identity_count=1,scan_total=9)
    reject('semi-inverted-proof-side',group_result,one,group_expected,
           lambda v:v['candidates'][0]['proof_bindings'][0].update(path=['L']),
           relation='method_defs',identity_mode='tuple',identity_count=1,scan_total=9)
    reject('semi-wrong-proof-entity',group_result,one,group_expected,
           lambda v:v['candidates'][0]['proof_bindings'][0]['entity'].update(local_index=3),
           relation='method_defs',identity_mode='tuple',identity_count=1,scan_total=9)
    nonmember=label(scan('method_refs',{'name':'abstractMethod'}),'outside')
    nonmember_group={'op':'group_by_owner','inputs':[join(method,nonmember,'local_definition')],
                     'required_roles':['outside'],'role_policy':'shared'}
    run_case('group-role-not-borrowed-from-reference',one,nonmember_group,[],
             check_options={'relation':'class_defs','identity_count':0,'scan_total':2})
    outside=label(scan('method_defs',{'name':'abstractMethod'},slot1),'outside')
    cross_join=join(scan('method_defs',{'name':'abstractMethod'},slot0),outside,'symbol')
    cross_group={'op':'group_by_owner','inputs':[cross_join], 'required_roles':['outside'],'role_policy':'shared'}
    run_case('group-role-not-borrowed-from-other-occurrence',two,cross_group,[],
             check_options={'relation':'class_defs','identity_count':0,'scan_total':2})

    external=('field_refs',0,3);ext_scan=scan('field_refs',{'has_local_definition':False})
    unknown_scan=scan('field_refs',{'flags_contains':8})
    run_case('semi-unknown-not-absence',one,join(ext_scan,unknown_scan,op='semi_join'),[],
             check_options={'relation':'field_refs','unknown':1,'complete':False,'identity_count':0,'scan_total':8})
    confirmed=semi(Row(external),Row(external),'same_entity')
    dominance=run_case('semi-true-witness-dominates-unknown',one,join(ext_scan,union(unknown_scan,ext_scan),op='semi_join'),[confirmed],
                       check_options={'relation':'field_refs','identity_count':1,'scan_total':12})
    assert all(w['matched'] is not None for w in dominance['candidates'][0]['evidence'])
    partial=Oracle(root,[source],False);slot=partial.dataset['inputs'][0]['slot_key']
    absent=scan('field_refs',{'name':'missing'})
    run_case('semi-missing-right-scope-unknown',partial,join(scan('field_refs',{'has_local_definition':False},slot),absent,op='semi_join'),[],
             incomplete=True,check_options={'relation':'field_refs','unknown':1,'complete':False,'reason':'SourceScopeIncomplete','identity_count':0,'scan_total':8})
    run_case('semi-known-empty-right-scope',partial,join(scan('field_refs',{'has_local_definition':False},slot),scan('field_refs',{'name':'missing'},slot),op='semi_join'),[],
             incomplete=True,check_options={'relation':'field_refs','identity_count':0,'scan_total':8})

    # The incomplete snapshot can contain only one of the two matches below;
    # a missing source may add a second member that invalidates max=1.
    # Build a separate valid DEX without changing the original input fixture.
    original=source.read_bytes();catalog=raw_entities(source,root)
    base_class=next(c for c in catalog['class_defs'] if c['type_descriptor']=='Lcatalog/Base;')
    data_at=struct.unpack_from('<I',original,base_class['record_offset']+24)[0]
    assert original[data_at:data_at+8]==bytes.fromhex('01 01 00 00 01 09 00 01')
    variant=bytearray(original);variant[data_at:data_at+8]=bytes.fromhex('02 00 00 00 00 09 01 09')
    variant[12:32]=hashlib.sha1(variant[32:]).digest();struct.pack_into('<I',variant,8,zlib.adler32(variant[12:])&0xffffffff)
    variant_path=out/'group-max-second-source.dex';variant_path.write_bytes(variant)
    independent_variant=raw_entities(variant_path,root)
    base_definitions=[f for f in independent_variant['field_defs'] if f['owner']=='Lcatalog/Base;']
    assert [(f['reference_index'],f['access_flags']) for f in base_definitions]==[(0,9),(1,9)]
    assert [(independent_variant['field_refs'][i]['access_flags'],independent_variant['field_refs'][i]['has_local_definition']) for i in (0,1)]==[(9,True),(9,True)]
    assert bytes(variant[data_at:data_at+8])==bytes.fromhex('02 00 00 00 00 09 01 09')
    assert source.read_bytes()==original
    full=Oracle(root,[source,variant_path]);left_slot=full.dataset['inputs'][0]['slot_key']
    assert left_slot==slot
    left_base=scan('field_defs',{'owner':'Lcatalog/Base;'},left_slot)
    flagged=scan('field_refs',{'flags_contains':8})
    owner_cap={'op':'group_by_owner','inputs':[join(left_base,flagged,'symbol')],'min':1,'max':1}
    partial_group=run_case('group-max-incomplete-right',partial,owner_cap,[],incomplete=True,intent='unique',
                           check_options={'relation':'class_defs','unknown':1,'complete':False,'decision':'Undetermined',
                                          'reason':'SourceScopeIncomplete','identity_count':0,'scan_total':7})
    partial_ops=partial_group['relation_profile']['operators']
    assert [(p['output_rows'],p['unknown_rows']) for p in partial_ops if p['op']=='join']==[(1,0)]
    assert [(p['output_rows'],p['unknown_rows']) for p in partial_ops if p['op']=='group_by_owner']==[(1,1)]
    reject('group-incomplete-forged-unique',partial_group,partial,[],
           lambda v:v.update(coverage='Complete',decision='ProvenTrue',reason='None',unknown_rows=0),
           relation='class_defs',unknown=1,complete=False,decision='Undetermined',reason='SourceScopeIncomplete',identity_count=0,scan_total=7)
    full_group=run_case('group-max-complete-second-source',full,owner_cap,[],intent='unique',
                        check_options={'relation':'class_defs','decision':'ProvenFalse','reason':'NoMatch','identity_count':0,'scan_total':11})
    full_ops=full_group['relation_profile']['operators']
    assert [(p['output_rows'],p['unknown_rows']) for p in full_ops if p['op']=='join']==[(3,0)]
    assert [(p['output_rows'],p['unknown_rows']) for p in full_ops if p['op']=='group_by_owner']==[(0,0)]
    assert partial_group['query_id']==full_group['query_id']
    reject('group-complete-forged-candidate',full_group,full,[],lambda v:v['candidates'].append({}),
           relation='class_defs',decision='ProvenFalse',reason='NoMatch',identity_count=0,scan_total=11)
    bad_scope=call('missing-slot',one,join(scan('field_defs',slot='no-such-slot'),scan('field_refs'),'local_definition'),code=2)
    assert bad_scope['execution_status']=='SourceMismatch'
    too_small=call('intermediate-budget',one,join(twice,thrice),code=3,max_intermediate_rows=1)
    assert too_small['execution_status']=='BudgetExceeded'
    incompatible=call('incompatible-join',one,join(scan('field_defs'),scan('method_defs')),code=2)
    assert incompatible['execution_status']=='Unsupported'
    ranked=run_case('topn-after-join',one,join(scan('field_defs'),scan('field_refs'),'local_definition'),field_pairs[:1],
                    intent='top_n',max_results=1,order_by=[{'field':'name','direction':'desc'}],
                    check_options={'relation':'field_defs','identity_count':3,'scan_total':7,'decision':'ProvenTrue','max_results':1})
    assert ranked['query_profile']['order_verified'] and ranked['candidates'][0]['name']=='shared'

    golden={}
    for key,expected_hash in [('same_entity','808dfb27acbf6a904286be086551eca3b00e8175e0cf40f415c331fe15bd8d8d'),
                              ('symbol','1a580e7b9b3089e7d5f77b9cbf30dddf3ec7d07d0cbf2e12728a953cb09e25a5')]:
        query_id=golden_join_query_id(key);assert query_id=='query:v3:'+expected_hash
        result=run_case('golden-join-'+key,one,join(scan('method_defs'),scan('method_defs'),key),
                        [paired(Row(method_key),Row(method_key),key)],max_results=4096,
                        check_options={'relation':'method_defs','identity_count':1,'scan_total':2})
        assert result['query_id']==query_id and result['query']['required_capabilities']==2563
        golden[key]={'query_id':query_id,'canonical_bytes':324}
    assert golden['same_entity']['query_id']!=golden['symbol']['query_id']

    # Golden hashes are from previous independent byte encodings, not the new native compiler.
    old_query={'return_type':'I','parameters':[],'using_strings':{'all':[{'op':'exact','value':'quality settings:'}]}}
    legacy=call('legacy-method-hash',one,'method_defs',where=old_query,intent='unique',max_results=2,evidence_profile='minimal')
    assert legacy['profile']=='dex-query-method-v1' and legacy['query_id']=='query:v1:283ae5fd16c5c58a2c7690abdb0b7cfb3a8edf7644c63cf5b43956967d8e4a63'
    entity=call('legacy-entity-hash',one,'field_defs',max_results=4096)
    assert entity['profile']=='dex-query-entity-v2' and entity['query_id']=='query:v2:6d119cc5d61d304582f915944e04db2a8b482aad25d7a694f6024907308a185a'
    graph=call('legacy-graph-hash',one,scan('method_defs'),max_results=4096)
    assert graph['profile']=='dex-query-relational-v3' and graph['query_id']=='query:v3:d3b9d916113de0403046db0ee9b5b4247591d5ccc2904e17809eadace97eff23'
    assert hashlib.sha256(exe.read_bytes()).hexdigest()==exe_sha
    summary={'passed':len(records),'failed':0,'forged_evidence_rejected':len(rejected),'rejected_controls':rejected,
             'executable_sha256':exe_sha,'fixture_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [source,method_source,variant_path]},
             'old_query_id_golden_checked':['method-v1','entity-v2','default-scan-v3'],
             'join_query_id_golden':{'shape':'join over two unfiltered method_defs scans; default enumerate/max_results=4096/bag; capability 2563','keys':golden},
             'coverage':'Authored Join/SemiJoin cases and raw metadata/identity oracle; no BoundedExpand, runtime dispatch, device, or performance proof',
             'evidence':str(out)}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8');return summary


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,required=True);a=p.parse_args()
    print(json.dumps(run(a.exe.resolve(),a.root.resolve()),indent=2))
