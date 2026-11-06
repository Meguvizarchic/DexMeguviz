"""Independent evidence checker for bounded v14 scan and filter-chain subsets.

The query must be an unscoped, unsorted enumerate scan or up to eight filters with static
reflection flags leaves, default projection/work bounds and explicit capabilities.
Other shapes are rejected rather than partially verified. It reuses the existing
independent DEX parser/entity catalog and occurrence identity implementation.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

RELATIONS = {'method_defs': (0,7), 'class_defs': (1,8), 'field_defs': (2,11),
             'method_refs': (3,7), 'field_refs': (4,11), 'type_refs': (6,8)}
MODES = {'contains':11, 'exact':12, 'any':13}

class Unsupported(ValueError): pass
class InvalidEvidence(ValueError): pass

def check(condition, message):
    if not condition: raise InvalidEvidence(message)

def strict_equal(a,b):
    if type(a) is not type(b):return False
    if isinstance(a,dict):return set(a)==set(b) and all(strict_equal(a[k],b[k]) for k in a)
    if isinstance(a,list):return len(a)==len(b) and all(strict_equal(x,y) for x,y in zip(a,b))
    return a==b
def parse_leaf(where, relation):
    if not isinstance(where,dict) or len(where)!=1 or next(iter(where)) not in ('flags','owner_flags'):
        raise Unsupported('one flags predicate required')
    target=next(iter(where)); predicate=where[target]
    if target=='owner_flags' and relation not in ('method_defs','method_refs','field_defs','field_refs'):
        raise Unsupported('owner_flags requires a member relation')
    if not isinstance(predicate,dict) or set(predicate)!={'domain','mode','value'} or predicate['domain']!='reflection' or predicate['mode'] not in MODES:
        raise Unsupported('unsupported predicate')
    value=predicate['value']
    if type(value) is not int or not 0<=value<=0xffffffff:raise Unsupported('invalid integer')
    return (target,predicate['mode'],value)


def parse_query(query):
    if not isinstance(query,dict) or set(query) - {'schema_version','relation','intent','required_capabilities','max_results'}:
        raise Unsupported('unsupported top-level query')
    if type(query.get('schema_version')) is not int or query.get('schema_version') != 1 or query.get('intent','enumerate') != 'enumerate':
        raise Unsupported('only v1 enumerate')
    caps=query.get('required_capabilities')
    if not isinstance(caps,list) or len(caps)!=2 or any(type(x) is not str for x in caps) or set(caps)!={'reflection_flags_static','reflection_relational'}:
        raise Unsupported('two explicit reflection capabilities required')
    limit=query.get('max_results',4096)
    if type(limit) is not int or not 1<=limit<=100000:raise Unsupported('invalid integer')
    node=query.get('relation'); filters=[]
    while isinstance(node,dict) and node.get('op')=='filter':
        if set(node)!={'op','input','where'} or len(filters)>=8:raise Unsupported('unsupported filter chain')
        filters.append(node['where']);node=node['input']
    if not isinstance(node,dict) or set(node)-{'op','relation','where'} or node.get('op')!='scan' or node.get('relation') not in RELATIONS:
        raise Unsupported('only filter chains over a supported scan')
    relation=node['relation']; raw=node.get('where',True)
    scan=None if raw is True else parse_leaf(raw,relation)
    leaves=[parse_leaf(where,relation) for where in filters]
    if scan is None and not leaves:raise Unsupported('reflection predicate required')
    return relation,leaves,scan,limit


def chain_query_id(relation,filters,scan,limit):
    rel,projection=RELATIONS[relation];caps=6292226 if rel else 6291971
    def pred(leaf):
        if leaf is None:return struct.pack('<6I',0,0,0,0,0xffffffff,0)
        target,mode,value=leaf
        return struct.pack('<6I', MODES[mode],0,3 if target=='owner_flags' else 2,value,0xffffffff,0)
    def frame(data):return struct.pack('<Q',len(data))+data
    def node(op,leaf,child=None):
        return struct.pack('<III',op,rel,1)+frame(pred(leaf))+struct.pack('<10I',0,1,0xffffffff,1,0,0,0,0,0,0 if child is None else 1)+(b'' if child is None else frame(child))
    encoded=node(0,scan)
    for leaf in reversed(filters):encoded=node(1,leaf,encoded)
    top=struct.pack('<IIIQIIIIIIII',rel,0,limit,100000000,projection,1,0,caps,0,100000,0,0)
    return 'query:v14:'+hashlib.sha256(b'DexMeguviz:QueryIR:reflection-relational-v14'+top+encoded).hexdigest()


def query_id(relation,target,mode,value,limit):
    # Kept for users of the original single-scan helper.
    return chain_query_id(relation,[],(target,mode,value),limit)

def reflection(raw,kind,annotations_absent=False):
    if raw is None:return None
    vis=raw & 7
    if vis and vis & (vis-1):return None
    if kind=='method':
        if raw & ~(0x1dff|0x30000) or raw & 0x20 and not raw & 0x100:return None
        flags=raw & ~0x100 if raw & 0x400 else raw
        return ((flags & ~0x20) | (0x20 if raw & 0x20000 else 0)) & 0xffff
    if kind=='field':return None if raw & ~0x50df else raw & 0xffff
    if kind=='class':return None if not annotations_absent or raw & ~0x7611 else raw & 0xffff
    raise Unsupported('unrecognized entity')

def verify(root, dex, query, result):
    if not __debug__:raise RuntimeError('Python assertions must be enabled for underlying independent parser')
    relation,filters,scan,limit=parse_query(query)
    root=Path(root).resolve(); dex=Path(dex).resolve()
    sys.path.insert(0,str(root/'tests/integration'));sys.path.insert(0,str(root/'tools/evidence_verifier'))
    from relational_test import Oracle
    from multisource import verify_metadata
    oracle=Oracle(root,[dex]);data=dex.read_bytes()
    classes={row['type_descriptor']:row for (kind,source,_),row in oracle.entities.items() if kind=='class_defs' and source==0}
    rows=[(key,row) for key,row in oracle.entities.items() if key[0]==relation and key[1]==0]
    def select(row,leaf):
        if leaf is None:return True
        target,mode,mask=leaf
        owner=classes.get(row.get('owner')) if 'owner' in row else classes.get(row.get('type_descriptor'))
        if target=='owner_flags':raw=owner['access_flags'] if owner else None;kind='class'
        else:
            raw=row['access_flags'];kind='class' if relation in ('class_defs','type_refs') else ('method' if relation.startswith('method') else 'field')
        absent=bool(owner is not None and struct.unpack_from('<I',data,owner['record_offset']+20)[0]==0)
        projected=reflection(raw,kind,absent)
        if projected is None:return None
        return {'contains':(projected & mask)==mask,'exact':projected==mask,'any':bool(projected & mask)}[mode]
    if len(rows)>100000:raise Unsupported('intermediate-limit execution unsupported')
    depth=len(filters); states={key:select(row,scan) for key,row in rows}
    states={key:value for key,value in states.items() if value is not False}
    def metric(node,op,inputs,states,scanned):
        unknown=sum(value is None for value in states.values())
        return {'node_id':node,'op':op,'input_rows':inputs,'output_rows':len(states),'unknown_rows':unknown,
                'visited_rows':scanned,'total_rows':scanned,'complete':unknown==0}
    profiles=[metric(depth,'scan',len(rows),states,len(rows))]
    for index in range(depth-1,-1,-1):
        inputs=len(states);next_states={}
        for key,prior in states.items():
            value=select(oracle.entities[key],filters[index])
            if value is False:continue
            next_states[key]=None if prior is None or value is None else True
        states=next_states
        profiles.append(metric(index,'filter',inputs,states,0))
    known=[key for key,value in states.items() if value is True]
    unknown=sum(value is None for value in states.values())
    if len(known)>limit:raise Unsupported('result-limit execution unsupported')
    expected_top={'schema_version','profile','command','execution_status','coverage','decision','reason','relation','visited_rows','total_rows','unknown_rows','counter_domain','source_sha256','content_id','occurrence_id','logical_dex_id','dex_version','snapshot_id','scope_complete','input_count','source_count','input_bytes','dex_bytes','source_bytes','inputs','sources','validation','budgets','query_id','query','query_scope','query_profile','relation_profile','candidates'}
    check(isinstance(result,dict) and set(result)==expected_top and result['command']=='query','unexpected top-level result shape')
    rel_id,projection=RELATIONS[relation];caps=6291971 if rel_id==0 else 6292226
    check(strict_equal(result['query'],{'node_count':depth+2,'required_capabilities':caps,'demand_mask':0,'projection_mask':projection,'intent':0,'max_results':limit,'max_work':100000000}),'query description mismatch')
    validation={'metadata_scope':'header,id_tables,class_data,type_lists,code_item_bounds,class_topology','metadata_subset_checked':True,'instruction_stream':'NotPerformed','instruction_methods_checked':0,'control_flow':'NoCFGOrTypeVerification','checksum':'SeePerLayer','dex_checksum':'NotVerified','archive_checks':'PerInputAndSource','runtime_binding':'NotPerformed','source_revision':'Unverified'}
    check(strict_equal(result['validation'],validation),'validation claims mismatch')
    check(strict_equal(result['source_bytes'],len(data)),'source byte count mismatch')
    expected_budget={'engine_owned_limit_bytes':536870912,'cli_input_buffer_limit_bytes':536870912,'max_single_input_bytes':536870912,'max_total_dex_bytes':536870912,'caller_input_peak_bytes':len(data),'caller_input_retained_bytes':0,'json_output_limit_bytes':8388608,'limits_process_rss':False}
    budget=result['budgets'];check(isinstance(budget,dict) and set(budget)==set(expected_budget)|{'engine_owned_bytes','engine_peak_owned_bytes'} and all(strict_equal(budget[k],v) for k,v in expected_budget.items()),'budget shape mismatch')
    used,peak=budget['engine_owned_bytes'],budget['engine_peak_owned_bytes'];check(type(used) is int and type(peak) is int and 0<=used<=peak<=536870912,'invalid memory accounting')
    qp=result['query_profile'];fixed={'fact_requests':0,'methods_decoded':0,'code_units':0,'string_pool_lookups':0,'invoke_sites':0,'field_uses':0,'declared_fields':0,'matches_seen':len(known),'sort_comparisons':0,'unknown_rows':unknown,'order_verified':unknown==0}
    check(isinstance(qp,dict) and set(qp)==set(fixed)|{'work_units'} and all(strict_equal(qp[k],v) for k,v in fixed.items()),'query profile mismatch')
    check(type(qp['work_units']) is int and len(rows)<=qp['work_units']<=100000000,'invalid work accounting')
    check(result.get('execution_status')=='Complete','execution incomplete')
    check(result.get('profile')=='dex-query-reflection-relational-v14' and result.get('query_id')==chain_query_id(relation,filters,scan,limit),'profile or QueryID mismatch')
    metadata=dict(result);metadata['profile']='dex-query-method-v1';verify_metadata(oracle.dataset,metadata)
    # The existing verifier checks values; additionally distinguish JSON booleans
    # from integers for every independently known source identity field.
    for actual,expected,fields in ((result['inputs'][0],oracle.dataset['inputs'][0],('input_index','slot_key','role','format','source_sha256','content_id','input_bytes','source_count','allow_no_dex','expected_digest_verified')),(result['sources'][0],oracle.dataset['sources'][0],('source_index','input_index','slot_key','role','source_sha256','source_bytes','archive_sha256','content_id','occurrence_id','logical_dex_id','counts'))):
        check(all(strict_equal(actual.get(field),expected[field]) for field in fields),'source field type or value mismatch')
    input_expected=oracle.dataset['inputs'][0];source_expected=oracle.dataset['sources'][0]
    input_fields=('input_index','slot_key','role','format','source_sha256','content_id','input_bytes','source_count','allow_no_dex','expected_digest_verified')
    expected_input={k:input_expected[k] for k in input_fields};expected_input['container_metadata_checked']=True
    check(strict_equal(result['inputs'][0],expected_input),'input metadata shape mismatch')
    source_fields=('source_index','input_index','slot_key','role','source_sha256','source_bytes','archive_sha256','content_id','occurrence_id','logical_dex_id','counts')
    expected_source={k:source_expected[k] for k in source_fields}
    expected_source.update(snapshot_id=oracle.dataset['snapshot_id'],dex_version=int(source_expected['version']),archive_entry_name='',archive_entry_index=None,crc_verified=False,header_consistency_verified=False,expected_digest_verified=False,local_scope=({'relation':relation,'logical_header_offset':0,'method_index_domain':'logical_dex_id'} if relation=='method_defs' else {'relation':relation,'logical_header_offset':0,'local_index_domain':'logical_dex_id,relation'}))
    check(strict_equal(result['sources'][0],expected_source),'source metadata shape mismatch')
    # Verify the complete single-source compatibility projection with exact
    # JSON types: Python considers integral floats equal to integers.
    top_source={field:source_expected[field] for field in ('source_sha256','content_id','occurrence_id','logical_dex_id')}
    top_source.update(dex_version=int(source_expected['version']),snapshot_id=oracle.dataset['snapshot_id'],scope_complete=True,source_bytes=len(data))
    check(all(strict_equal(result[field],expected) for field,expected in top_source.items()),'top-level source compatibility mismatch')
    for field,expected in (('schema_version',1),('input_count',1),('source_count',1),('input_bytes',len(data)),('dex_bytes',len(data))):
        check(strict_equal(result.get(field),expected),'top-level metadata type mismatch: '+field)
    check(result.get('relation')==relation and result.get('counter_domain')=='scan_records','relation/counter mismatch')
    check(strict_equal(result.get('total_rows'),len(rows)) and strict_equal(result.get('visited_rows'),len(rows)) and strict_equal(result.get('unknown_rows'),unknown),'scan counts mismatch')
    check(result.get('coverage')==('Partial' if unknown else 'Complete') and result.get('reason')==('UnknownAttribute' if unknown else 'None') and result.get('decision')=='NotApplicable','coverage/decision mismatch')
    scope=result.get('query_scope',{});check(strict_equal(scope,{'explicit':False,'complete':True,'sources':[0]}),'scope mismatch')
    profile=result.get('relation_profile',{});operators=profile.get('operators',[])
    check(isinstance(profile,dict) and set(profile)=={'root_node','unique_by','identity_count','operators'} and strict_equal(profile.get('root_node'),0) and profile.get('unique_by')=='entity' and strict_equal(profile.get('identity_count'),len(known)) and strict_equal(operators,profiles),'graph profile mismatch')
    candidates=result.get('candidates');check(isinstance(candidates,list) and len(candidates)==len(known),'candidate count mismatch')
    seen=set()
    for actual in candidates:
        key=(actual.get('relation'),actual.get('source_index'),actual.get('local_index'))
        check(type(key[0]) is str and type(key[1]) is int and type(key[2]) is int and key in known and key not in seen,'invalid or duplicate candidate');seen.add(key)
        oracle.check_entity(actual,key)
        origin=oracle.dataset['sources'][0]
        expected_candidate=dict(oracle.entities[key]);expected_candidate.update(relation=relation,source_index=0,input_index=origin['input_index'],source_sha256=origin['source_sha256'],content_id=origin['content_id'],occurrence_id=origin['occurrence_id'],logical_dex_id=origin['logical_dex_id'],snapshot_id=oracle.dataset['snapshot_id'],bindings=[],evidence=actual.get('evidence'))
        check(strict_equal(actual,expected_candidate),'candidate shape, field type or value mismatch')
        check(actual.get('bindings')==[] and actual.get('links',[])==[] and actual.get('proof_bindings',[])==[] and len(actual.get('evidence',[]))==depth+1,'unexpected evidence, links or bindings')
        for witness,operator in zip(actual['evidence'],range(depth,-1,-1)):
            expected={'kind':'metadata','node_id':operator+1,'matched':True,'dex_pc':None,'opcode':None,'reference_index':None,'reference_kind':None,'extra_proto':None,'code_units':0,'operator_node':operator,'entity':{'relation':key[0],'source_index':key[1],'local_index':key[2]}}
            check(strict_equal(witness,expected),'metadata witness mismatch')
    check(seen==set(known),'missing candidates')
    return {'verified':True,'query_id':chain_query_id(relation,filters,scan,limit),'source_sha256':hashlib.sha256(data).hexdigest(),'known_rows':len(known),'unknown_rows':unknown,'scope':'one-source, complete, unscoped v14 reflection scan/filter chain; static metadata only','bounded_only_not_independently_recomputed':['query_profile.work_units','budgets.engine_owned_bytes','budgets.engine_peak_owned_bytes']}

def main():
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--dex',type=Path,required=True);p.add_argument('--query',type=Path,required=True);p.add_argument('--result',type=Path,required=True)
    def unique_pairs(pairs):
        out={}
        for key,value in pairs:
            if key in out:raise ValueError('duplicate JSON key: '+key)
            out[key]=value
        return out
    def reject_constant(value):raise ValueError('non-finite JSON number: '+value)
    a=p.parse_args();parse=lambda path:json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=unique_pairs,parse_constant=reject_constant)
    print(json.dumps(verify(a.root,a.dex,parse(a.query),parse(a.result)),ensure_ascii=False))
if __name__=='__main__':main()











