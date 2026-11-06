"""Independent raw DEX oracle for authored use-relation CLI cases.

This checks structural references, not ART loading or bootstrap semantics.
"""
from pathlib import Path
from collections import Counter
import argparse, copy, hashlib, json, struct, subprocess, sys, time, zlib

sys.dont_write_bytecode = True

# SHA and instruction expectations are fixed independently of CLI output.
FIXTURES = {
    'two-invokes.dex': ('04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b', [
        ('invoke_sites', 0, 0x71, 'method_ref', 4, None), ('invoke_sites', 3, 0x71, 'method_ref', 4, None)]),
    'field-read-write.dex': ('7558a8945c3a87f727de782d885c687539d839e460497f6d2e86c2a7c7f46e8d', [
        ('field_uses', 0, 0x60, 'field_ref', 0, None), ('field_uses', 2, 0x67, 'field_ref', 0, None)]),
    'string-normal-jumbo.dex': ('65373dc14bb0b19b3fb4ae8fd236e83befbfee4b69b74e3a8d4a8b7db2637c04', [
        ('string_uses', 0, 0x1a, 'string_value', 10, None), ('string_uses', 2, 0x1b, 'string_value', 10, None)]),
    'valid-then-corrupt.dex': ('4e0661d233cfc3eaf32aff66e615a1cacba822e768c3c3b4559f0f0abfc2c2be', [
        ('string_uses', 0, 0x1a, 'string_value', 10, None), ('invoke_sites', 2, 0x71, 'method_ref', 4, None)]),
    'method-uses.dex': ('8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc', [
        ('string_uses', 0, 0x1a, 'string_value', 10, None), ('invoke_sites', 2, 0x71, 'method_ref', 4, None),
        ('field_uses', 5, 0x60, 'field_ref', 0, None)]),
    'invoke-domains-038.dex': ('ecf85d163c87d58f065335f0d932442be48b91b5efa3858e319a1c1cdf7313b0', [
        ('invoke_sites', 0, 0xfa, 'method_and_proto', 4, 0), ('invoke_sites', 4, 0xfc, 'call_site', 0, None)])}
GOLDEN = {
    'string_uses': (7, 4642, 'f5bc0cb196ad27f6541a38ec4e139bf1ad57f1e4d3d436f06d1841afa05c8f61'),
    'invoke_sites': (8, 4674, 'c026266fb392c395224c2d8659d259303e4e112a62ee7d18a12dd725ae4ad90f'),
    'field_uses': (9, 4738, 'ff6b66773d149769cb381f7561be4a20cfb32359408c16636936c7d5418346fb')}


def golden_id(relation):
    number, caps, expected = GOLDEN[relation]
    u32 = lambda n: struct.pack('<I', n)
    u64 = lambda n: struct.pack('<Q', n)
    frame = lambda b: u64(len(b)) + b
    predicate = b''.join(u32(n) for n in (0, 0, 0, 0, 0xffffffff, 0))
    top = b''.join(u32(n) for n in (number, 0, 4096)) + u64(100000000)
    top += b''.join(u32(n) for n in (7, 1, 0, caps, 0, 100000, 0, 0))
    node = b''.join(u32(n) for n in (0, number, 1)) + frame(predicate)
    node += b''.join(u32(n) for n in (0, 1, 0xffffffff, 1, 0, 0, 0, 0, 0, 0))
    canonical = b'DexMeguviz:QueryIR:use-v4' + top + node
    assert len(canonical) == 161 and hashlib.sha256(canonical).hexdigest() == expected
    return 'query:v4:' + expected


def raw_fixture(path):
    digest, records = FIXTURES[path.name]
    data = path.read_bytes()
    expected_size = 664 if path.name == 'invoke-domains-038.dex' else 608
    assert len(data) == expected_size and hashlib.sha256(data).hexdigest() == digest
    assert data[12:32] == hashlib.sha1(data[32:]).digest()
    assert struct.unpack_from('<I', data, 8)[0] == zlib.adler32(data[12:]) & 0xffffffff
    assert struct.unpack_from('<I', data, 32)[0] == len(data)
    u16 = lambda offset: struct.unpack_from('<H', data, offset)[0]
    u32 = lambda offset: struct.unpack_from('<I', data, offset)[0]
    assert u32(416 + 12) == 8 and u32(396 + 12) == 1 and u16(396 + 16) & 255 == 0x0e
    for relation, pc, opcode, domain, target, proto in records:
        at = 416 + 16 + pc * 2
        assert u16(at) & 255 == opcode
        raw_target = u16(at + 2)
        if opcode == 0x1b: raw_target |= u16(at + 4) << 16
        assert raw_target == target
        if opcode == 0xfa: assert u16(at + 6) == proto
        assert (opcode, domain) in {(0x1a, 'string_value'), (0x1b, 'string_value'),
            (0x60, 'field_ref'), (0x67, 'field_ref'), (0x71, 'method_ref'),
            (0xfa, 'method_and_proto'), (0xfc, 'call_site')}
        if domain == 'call_site':
            map_off = u32(52); map_size = u32(map_off)
            call_sites = [struct.unpack_from('<HHII', data, map_off + 4 + i * 12)
                          for i in range(map_size) if u16(map_off + 4 + i * 12) == 7]
            assert len(call_sites) == 1 and target < call_sites[0][2]
        else:
            count_offset = {'string_value': 56, 'field_ref': 80, 'method_ref': 88, 'method_and_proto': 88}[domain]
            assert target < u32(count_offset)
        if proto is not None: assert proto < u32(72)
    if path.name == 'valid-then-corrupt.dex': assert u16(416 + 16 + 5 * 2) & 255 == 0x73
    return records


def scan(relation, where=None, slot=None):
    value = {'op': 'scan', 'relation': relation}
    if where is not None: value['where'] = where
    if slot is not None: value['scope'] = {'slots': [slot]}
    return value


def join(left, right, key): return {'op': 'join', 'left': left, 'right': right, 'on': key}
def key(item): return (item['relation'], item['source_index'], item['local_index'], item['dex_pc'])
def event(source, spec): return (spec[0], source, 2, spec[1])
def entity(relation, source, local): return (relation, source, local, None)


def run(exe, root):
    sys.path.insert(0, str(root/'tests/integration'))
    sys.path.insert(0, str(root/'tools/evidence_verifier'))
    from relational_test import Oracle
    from multisource import verify_metadata
    directory = root/'tests/fixtures/generated'
    paths = {name: directory/('method_facts' if name in ('method-uses.dex', 'invoke-domains-038.dex') else 'use_relations')/name for name in FIXTURES}
    authored = {name: raw_fixture(path) for name, path in paths.items()}
    out = root/'docs/evidence/use-query'/('run-'+str(time.time_ns())); out.mkdir(parents=True)
    exe_sha = hashlib.sha256(exe.read_bytes()).hexdigest()
    records, rejected = [], []

    def make(names, complete=True):
        o = Oracle(root, [paths[n] for n in names], complete)
        o.events = {event(s, spec): spec for s, name in enumerate(names) for spec in authored[name]}
        return o

    def value_check(item, o, binding=False):
        k = key(item)
        if k[0] in GOLDEN:
            assert k in o.events and item['value_kind'] == 'use'
            _, pc, opcode, domain, target, proto = o.events[k]
            assert item['caller_ordinal'] == 2 and item['caller_method_ref'] == 3
            assert item['opcode'] == opcode and item['code_offset'] == 416
            assert item['instruction_offset'] == 432 + 2 * pc
            assert (item['target_domain'], item['target_index'], item['extra_proto']) == (domain, target, proto)
            assert (item['caller_owner'], item['caller_name'], item['caller_prototype']) == ('Lfacts/Example;', 'uses', '()V')
            if not binding:
                origin = o.dataset['sources'][k[1]]
                for field in ('input_index', 'source_sha256', 'content_id', 'occurrence_id', 'logical_dex_id'):
                    assert item[field] == origin[field]
                assert item['snapshot_id'] == o.dataset['snapshot_id']
        else:
            assert item['value_kind'] == 'entity' and k[3] is None
            o.check_entity(item, k[:3], binding)
        return k

    # Expected pair = (left identity, right identity, key); None means a plain scan.
    def check(v, o, expected, *, complete=True, decision='NotApplicable', reason='None',
              event_count=0, method_count=4, entity_count=0, scan_output=None, semi=False):
        assert v['profile'] == 'dex-query-use-v4' and v['counter_domain'] == 'per_operator'
        assert v['execution_status'] == 'Complete'
        assert (v['coverage'], v['decision'], v['reason']) == (('Complete' if complete else 'Partial'), decision, reason)
        assert v['unknown_rows'] == 0
        assert (v['method_visited'], v['method_total']) == (method_count, method_count)
        assert (v['entity_visited'], v['entity_total']) == (entity_count, entity_count)
        assert v['events_collected'] == event_count
        assert v['validation']['call_site_target_validation'] == 'IndexBoundsOnly'
        assert v['validation']['bootstrap'] == 'NotParsed'
        meta = dict(v); meta['profile'] = 'dex-query-method-v1'; verify_metadata(o.dataset, meta)
        assert v['query_id'].startswith('query:v4:')
        ops = v['relation_profile']['operators']; ids = {x['node_id']: x for x in ops}
        scans = [x for x in ops if x['op'] == 'scan']
        method_scans = [x for x in scans if x['scan_domain'] == 'method_defs']
        assert sum(x['visited'] for x in method_scans) == method_count
        assert sum(x['total'] for x in method_scans) == method_count
        assert sum(x['attempted_methods'] for x in method_scans) == method_count
        assert sum(x['no_body_methods'] for x in method_scans) == method_count // 2
        assert sum(x['decoded_methods'] for x in method_scans) == method_count // 2
        assert sum(x['events_collected'] for x in method_scans) == event_count
        assert sum(x['code_units'] for x in method_scans) == 9 * method_count // 4
        assert sum(x['visited'] for x in scans if x['scan_domain'] == 'entity_records') == entity_count
        if scan_output is not None: assert sum(x['output_rows'] for x in method_scans) == scan_output
        signatures = []
        for row in v['candidates']:
            primary = value_check(row, o)
            bindings = []
            for b in row['bindings']:
                bkey = value_check(b, o, True)
                bindings.append((b['label'], bkey, tuple(b['path'])))
            links = [(l['operator_node'], l['key'], key(l['left']), key(l['right'])) for l in row.get('links', [])]
            proofs = [(p['operator_node'], p['label'], value_check(p['value'], o, True), tuple(p['path'])) for p in row.get('proof_bindings', [])]
            identities = {primary, *(x[1] for x in bindings), *(x[2] for x in proofs)}
            assert row['evidence']
            for w in row['evidence']:
                wk = key(w['entity']); assert wk in identities and w['operator_node'] in ids
                if wk in o.events and w['dex_pc'] is not None:
                    spec = o.events[wk]
                    assert w['dex_pc'] == spec[1] and w['opcode'] == spec[2] and w['reference_index'] == spec[4]
                    assert w['extra_proto'] == spec[5]
                    assert w['reference_kind'] == {'string_value':'string','field_ref':'field',
                        'method_ref':'method','method_and_proto':'method_and_proto','call_site':'call_site'}[spec[3]]
            assert all(any(key(w['entity']) == x and w['dex_pc'] == x[3] for w in row['evidence']) for x in identities if x in o.events)
            signatures.append((primary, frozenset(bindings), tuple(sorted(links)), frozenset(proofs)))
        expected_signatures = []
        for left, right, link in expected:
            bs = frozenset() if right is None or semi else frozenset({(None, left, ('L',)), (None, right, ('R',))})
            ls = () if right is None else ((0, link, left, right),)
            ps = frozenset({(0, None, right, ('R',))}) if semi and right is not None else frozenset()
            expected_signatures.append((left, bs, ls, ps))
        assert Counter(signatures) == Counter(expected_signatures), (signatures, expected_signatures)

    def call(name, o, expression, *, code=0, incomplete=False, **options):
        query = {'schema_version': 1, 'relation': expression, 'max_results': 100, **options}
        qpath = out/(name+'.query.json'); qpath.write_text(json.dumps(query, indent=2), encoding='utf-8')
        command = [str(exe), 'query', str(o.paths[0]), '--query', str(qpath), '--json']
        for path in o.paths[1:]: command += ['--source', str(path)]
        if incomplete: command.append('--scope-incomplete')
        result = subprocess.run(command, capture_output=True, timeout=30)
        (out/(name+'.stdout.json')).write_bytes(result.stdout); (out/(name+'.stderr.log')).write_bytes(result.stderr)
        records.append({'name': name, 'command': command, 'exit_code': result.returncode,
                        'stdout_sha256': hashlib.sha256(result.stdout).hexdigest()})
        (out/'commands.json').write_text(json.dumps(records, indent=2)+'\n', encoding='utf-8')
        assert result.returncode == code, (name, result.returncode, result.stdout, result.stderr)
        value = json.loads(result.stdout)
        if code: assert value['coverage'] == 'Partial' and value['decision'] == 'Undetermined' and not value['candidates']
        return value

    def run_case(name, o, expr, expected, *, checks=None, incomplete=False, **options):
        v = call(name, o, expr, incomplete=incomplete, **options)
        check(v, o, expected, **(checks or {})); return v

    def reject(name, value, o, expected, mutate, **checks):
        v = copy.deepcopy(value); mutate(v)
        try: check(v, o, expected, **checks)
        except (AssertionError, KeyError, TypeError, ValueError): rejected.append(name)
        else: raise AssertionError('forged result accepted: '+name)

    for relation, filename in [('invoke_sites', 'two-invokes.dex'), ('field_uses', 'field-read-write.dex'),
                               ('string_uses', 'string-normal-jumbo.dex')]:
        o = make([filename]); keys = [event(0, s) for s in authored[filename]]
        expected = [(k, None, None) for k in keys]
        v = run_case('root-'+relation, o, scan(relation), expected, checks={'event_count': 2})
        reject(relation+'-wrong-pc', v, o, expected, lambda x:x['candidates'][0].update(dex_pc=99), event_count=2)
        reject(relation+'-wrong-domain', v, o, expected, lambda x:x['candidates'][0].update(target_domain='call_site'), event_count=2)
        reject(relation+'-missing-event', v, o, expected, lambda x:x['candidates'].pop(), event_count=2)
        reject(relation+'-wrong-source', v, o, expected, lambda x:x['candidates'][0].update(source_index=1), event_count=2)
        filtered = run_case('filtered-'+relation, o, scan(relation, {'pc': keys[1][3]}), [expected[1]],
                            checks={'event_count': 2, 'scan_output': 1})
        assert filtered['candidates'][0]['dex_pc'] == keys[1][3]
        sorted_v = run_case('sort-'+relation, o, scan(relation), list(reversed(expected)),
                            intent='top_n', order_by=[{'field':'pc','direction':'desc'}],
                            checks={'event_count': 2, 'decision':'ProvenTrue'})
        assert [x['dex_pc'] for x in sorted_v['candidates']] == [keys[1][3], keys[0][3]]
        for direction in (False, True):
            left, right = (scan('method_defs'), scan(relation)) if direction else (scan(relation), scan('method_defs'))
            pairs = [(entity('method_defs', 0, 2), k, 'caller') if direction else (k, entity('method_defs', 0, 2), 'caller') for k in keys]
            joined = run_case('caller-'+relation+('-reverse' if direction else ''), o, join(left, right, 'caller'), pairs,
                              checks={'event_count': 2, 'entity_count': 4})
            if direction:
                reject(relation+'-binding-pc', joined, o, pairs,
                       lambda x:next(b for b in x['candidates'][0]['bindings'] if b['value_kind']=='use').update(dex_pc=99),
                       event_count=2, entity_count=4)
        target_rel, target_id = {'invoke_sites':('method_refs',4), 'field_uses':('field_refs',0), 'string_uses':('string_values',10)}[relation]
        target_count = sum(1 for k in o.entities if k[0] == target_rel)
        for direction in (False, True):
            left, right = (scan(target_rel), scan(relation)) if direction else (scan(relation), scan(target_rel))
            target = entity(target_rel, 0, target_id)
            pairs = [(target,k,'target_ref') if direction else (k,target,'target_ref') for k in keys]
            run_case('target-'+relation+('-reverse' if direction else ''), o, join(left,right,'target_ref'), pairs,
                     checks={'event_count':2, 'entity_count':target_count})

    poly = make(['invoke-domains-038.dex']); specs = authored['invoke-domains-038.dex']
    poly_keys = [event(0,s) for s in specs]
    run_case('invoke-domains', poly, scan('invoke_sites'), [(k,None,None) for k in poly_keys], checks={'event_count':2})
    for domain, k in zip(('method_and_proto','call_site'),poly_keys):
        run_case('domain-'+domain, poly, scan('invoke_sites',{'target_domain':domain}), [(k,None,None)],
                 checks={'event_count':2, 'scan_output':1})
    target = entity('method_refs',0,4); count = sum(1 for k in poly.entities if k[0]=='method_refs')
    for reverse in (False, True):
        a,b = (scan('method_refs'),scan('invoke_sites')) if reverse else (scan('invoke_sites'),scan('method_refs'))
        pair = (target,poly_keys[0],'target_ref') if reverse else (poly_keys[0],target,'target_ref')
        run_case('poly-target'+('-reverse' if reverse else ''), poly, join(a,b,'target_ref'), [pair],
                 checks={'event_count':2,'entity_count':count})

    one = make(['two-invokes.dex']); only = event(0, authored['two-invokes.dex'][1]); method = entity('method_defs',0,2)
    semi_expr = {'op':'semi_join','left':scan('method_defs'), 'right':scan('invoke_sites',{'pc':3}), 'on':'caller'}
    semi_expected = [(method,only,'caller')]
    semiv = run_case('semi-proof-event-pc',one,semi_expr,semi_expected,
                     checks={'event_count':2,'entity_count':4,'semi':True})
    reject('semi-proof-wrong-pc',semiv,one,semi_expected,
           lambda x:x['candidates'][0]['proof_bindings'][0]['value'].update(dex_pc=99),
           event_count=2,entity_count=4,semi=True)

    two = make(['two-invokes.dex','two-invokes.dex']); events = [event(s,r) for s in range(2) for r in authored['two-invokes.dex']]
    run_case('two-occurrences',two,scan('invoke_sites'),[(k,None,None) for k in events], checks={'event_count':4,'method_count':8})
    assert two.dataset['sources'][0]['content_id']==two.dataset['sources'][1]['content_id']
    assert two.dataset['sources'][0]['occurrence_id']!=two.dataset['sources'][1]['occurrence_id']
    pairs=[(entity('method_defs',k[1],2),k,'caller') for k in events]
    run_case('same-source-caller-only',two,join(scan('method_defs'),scan('invoke_sites'),'caller'),pairs,
             checks={'event_count':4,'method_count':8,'entity_count':8})
    slot0,slot1=(two.dataset['inputs'][i]['slot_key'] for i in range(2))
    run_case('cross-source-caller-empty',two,join(scan('method_defs',slot=slot0),scan('invoke_sites',slot=slot1),'caller'),[],
             checks={'event_count':2,'entity_count':4})

    base = make(['method-uses.dex'])
    for relation in GOLDEN:
        keys = [event(0,s) for s in authored['method-uses.dex'] if s[0]==relation]
        v = run_case('golden-'+relation,base,scan(relation),[(k,None,None) for k in keys],
                     max_results=4096,checks={'event_count':len(keys)})
        assert v['query_id']==golden_id(relation) and v['query']['required_capabilities']==GOLDEN[relation][1]
    legacy=call('legacy-v1',base,'method_defs',where={'return_type':'I','parameters':[],'using_strings':{'all':[{'op':'exact','value':'quality settings:'}]}},intent='unique',max_results=2,evidence_profile='minimal')
    assert legacy['query_id']=='query:v1:283ae5fd16c5c58a2c7690abdb0b7cfb3a8edf7644c63cf5b43956967d8e4a63'
    assert call('legacy-v2',base,'field_defs',max_results=4096)['query_id']=='query:v2:6d119cc5d61d304582f915944e04db2a8b482aad25d7a694f6024907308a185a'
    assert call('legacy-v3',base,scan('method_defs'),max_results=4096)['query_id']=='query:v3:d3b9d916113de0403046db0ee9b5b4247591d5ccc2904e17809eadace97eff23'

    partial=make(['two-invokes.dex'],False); partial_keys=[event(0,s) for s in authored['two-invokes.dex']]
    partial_expected=[(k,None,None) for k in partial_keys]
    pv=run_case('incomplete',partial,scan('invoke_sites'),partial_expected,incomplete=True,
                checks={'complete':False,'event_count':2})
    reject('fake-complete',pv,partial,partial_expected,lambda x:x.update(coverage='Complete'),
           complete=False,event_count=2)
    missing=call('missing-scope',base,scan('invoke_sites',slot='no-such-slot'),code=2)
    assert missing['execution_status']=='SourceMismatch'
    limited=call('work-budget',base,scan('invoke_sites'),code=3,max_work=1)
    assert limited['execution_status']=='BudgetExceeded'
    corrupt=make(['valid-then-corrupt.dex'])
    failure=call('corrupt-after-hit',corrupt,scan('string_uses',{'pc':0}),code=2,intent='exists')
    assert failure['execution_status']=='CorruptInput' and failure['error']['offset']==442
    assert hashlib.sha256(exe.read_bytes()).hexdigest()==exe_sha
    summary={'passed':len(records),'failed':0,'forged_evidence_rejected':len(rejected),'rejected_controls':rejected,
             'executable_sha256':exe_sha,'fixture_sha256':{str(p):FIXTURES[n][0] for n,p in paths.items()},
             'scope':'Authored raw DEX instruction/reference and relation cases only; no ART, runtime, bootstrap or complete verifier claim.'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2)); return summary


if __name__ == '__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--exe',type=Path,required=True); parser.add_argument('--root',type=Path,required=True)
    args=parser.parse_args(); run(args.exe.resolve(),args.root.resolve())
