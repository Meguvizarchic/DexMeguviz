"""Relational CLI acceptance using independent raw entities and small set/bag oracles.

The oracle only implements the authored cases below. It does not call the C++
compiler/evaluator or accept coverage as a reason to omit expected candidates.
"""
from pathlib import Path
from collections import Counter
from dataclasses import dataclass
import argparse, copy, hashlib, itertools, json, re, struct, subprocess, sys, time

sys.dont_write_bytecode = True


def scan_method_query_id(max_results=4096):
    """Independent explicit-byte golden for an otherwise-default method scan.

    No graph/compiler introspection: relation/method=0, enumerate=0, projection=7,
    root bag=1, capabilities=metadata|method_defs|relational=515, entity unique=0.
    The scan has a true predicate, no label, min=1/max=UINT32_MAX, tuple identity,
    no bag/scope/distinct-role flags, and no slots/roles/children.
    """
    true_predicate = struct.pack('<6I', 0, 0, 0, 0, 0xffffffff, 0)
    top = struct.pack('<IIIQIIIIIIII', 0, 0, max_results, 100000000, 7, 1, 0, 515, 0, 100000, 0, 0)
    scan = struct.pack('<IIIQ', 0, 0, 1, len(true_predicate)) + true_predicate
    scan += struct.pack('<10I', 0, 1, 0xffffffff, 1, 0, 0, 0, 0, 0, 0)
    return 'query:v3:' + hashlib.sha256(b'DexMeguviz:QueryIR:relational-v3' + top + scan).hexdigest()


@dataclass
class Row:
    entity: tuple
    bindings: tuple = ()
    certain: bool = True


def binding_key(binding):
    label, entity = binding
    return (label is not None, label or '', entity)


def row_key(row, identity='tuple'):
    return row.entity if identity == 'entity' else (row.entity, tuple(sorted(row.bindings, key=binding_key)))


def distinct_rows(rows, identity='tuple'):
    result = []; positions = {}
    for row in rows:
        key = row_key(row, identity)
        if key not in positions:
            positions[key] = len(result); result.append(row)
        elif row.certain and not result[positions[key]].certain:
            result[positions[key]] = row
    return result


@dataclass
class Expr:
    spec: dict
    relation: str
    rows: list
    profiles: list
    sources: set
    source_complete: bool


def profile(op, inputs, rows, complete=True, scanned=0):
    unknown = sum(not row.certain for row in rows)
    return {'op': op, 'input_rows': inputs, 'output_rows': len(rows),
            'unknown_rows': unknown, 'visited_rows': scanned, 'total_rows': scanned,
            'complete': complete and not unknown}


class Oracle:
    def __init__(self, root, paths, scope_complete=True):
        sys.path.insert(0, str(root/'tests/integration'))
        sys.path.insert(0, str(root/'tools/evidence_verifier'))
        from entity_query_test import raw_entities
        from multisource import load_source_set
        self.paths = paths
        self.dataset = load_source_set([{'path': str(path)} for path in paths], root,
                                      scope_complete, root)
        self.entities = {}
        for source, path in enumerate(paths):
            catalog = raw_entities(path, root)
            catalog['method_defs'] = []
            class_order = {row['type_descriptor']: row['local_index'] for row in catalog['class_defs']}
            assert len(class_order) == len(catalog['class_defs'])
            # The metadata oracle sorts definitions by reference ID for its old
            # method contract. Entity ordinals instead follow class_defs order,
            # then encoded direct/virtual declarations within each class_data.
            definitions = sorted(self.dataset['sources'][source]['parsed']['definitions'],
                                 key=lambda row: (class_order[row['owner']], row['declaration_offset']))
            for index, definition in enumerate(definitions):
                catalog['method_defs'].append({
                    'local_index': index, 'reference_index': definition['method_index'],
                    'record_offset': definition['declaration_offset'], 'has_local_definition': True,
                    'definition_offset': definition['declaration_offset'],
                    **{key: definition[key] for key in ('owner', 'name', 'prototype', 'access_flags', 'code_offset')}})
            for relation, rows in catalog.items():
                for row in rows:
                    self.entities[(relation, source, row['local_index'])] = row

    def scan(self, relation='field_defs', where=None, select=None, sources=None):
        chosen = set(range(len(self.paths))) if sources is None else set(sources)
        explicit = sources is not None
        spec = {'op': 'scan', 'relation': relation}
        if where is not None: spec['where'] = where
        if explicit:
            spec['scope'] = {'slots': [self.dataset['inputs'][i]['slot_key'] for i in sorted(chosen)]}
        available = [(key, value) for key, value in self.entities.items()
                     if key[0] == relation and key[1] in chosen]
        rows = []
        for key, value in available:
            result = True if select is None else select(value)
            if result is not False: rows.append(Row(key, certain=result is True))
        complete = explicit or self.dataset['scope_complete']
        return Expr(spec, relation, rows, [profile('scan', len(available), rows, complete, len(available))], chosen, complete)

    def filter(self, source, where, select):
        rows = []
        for row in source.rows:
            result = select(self.entities[row.entity])
            if result is not False: rows.append(Row(row.entity, row.bindings, row.certain and result is True))
        return Expr({'op': 'filter', 'input': source.spec, 'where': where}, source.relation, rows,
                    [*source.profiles, profile('filter', len(source.rows), rows, source.source_complete)],
                    source.sources, source.source_complete)

    def label(self, source, label):
        rows = [Row(row.entity, tuple(sorted(set((*row.bindings, (label, row.entity))), key=binding_key)), row.certain)
                for row in source.rows]
        return Expr({'op': 'label', 'input': source.spec, 'label': label}, source.relation, rows,
                    [*source.profiles, profile('label', len(source.rows), rows, source.source_complete)],
                    source.sources, source.source_complete)

    def union(self, *sources, semantics='set', identity='tuple'):
        assert sources and len({source.relation for source in sources}) == 1
        incoming = [row for source in sources for row in source.rows]
        rows = incoming if semantics == 'bag' else distinct_rows(incoming, identity)
        complete = all(source.source_complete for source in sources)
        return Expr({'op': 'union', 'inputs': [source.spec for source in sources],
                     'semantics': semantics, 'identity': identity}, sources[0].relation, rows,
                    [*(p for source in sources for p in source.profiles), profile('union', len(incoming), rows, complete)],
                    set().union(*(source.sources for source in sources)), complete)

    def distinct(self, source, identity='tuple'):
        rows = distinct_rows(source.rows, identity)
        return Expr({'op': 'distinct', 'input': source.spec, 'identity': identity}, source.relation, rows,
                    [*source.profiles, profile('distinct', len(source.rows), rows, source.source_complete)],
                    source.sources, source.source_complete)

    def effective_root(self, source, options):
        if 'where' in options:
            where = options['where']
            # These authored root-filter cases use known exact name/owner attributes.
            # Reject unsupported oracle predicates instead of guessing their semantics.
            def select(raw):
                if type(where) is bool: return where
                assert isinstance(where, dict) and set(where) <= {'name', 'owner'}
                assert all(isinstance(value, str) for value in where.values())
                return all(raw[key] == value for key, value in where.items())
            source = self.filter(source, where, select)
        if options.get('semantics', 'bag') == 'set': source = self.distinct(source, 'tuple')
        return source

    def group(self, *sources, minimum=1, maximum=0xffffffff, roles=(), policy='shared'):
        assert sources
        incoming = [row for source in sources for row in source.rows]
        grouped = {}
        for row in distinct_rows(incoming):
            relation, source, _ = row.entity
            assert relation in ('method_defs', 'field_defs')
            owner = self.entities[row.entity]['owner']
            owners = [key for key, value in self.entities.items()
                      if key[0] == 'class_defs' and key[1] == source and value['type_descriptor'] == owner]
            assert len(owners) == 1
            grouped.setdefault(owners[0], []).append(row)
        rows = []
        for owner, members in grouped.items():
            known = {row.entity for row in members if row.certain}
            possible = {row.entity for row in members}
            bindings = tuple(sorted({binding for row in members
                                     for binding in ((None, row.entity), *row.bindings)}, key=binding_key))
            assignments = [{entity for label, entity in bindings if label == role} for role in roles]
            if policy == 'shared': possible_roles = all(assignments)
            else: possible_roles = any(len(set(choice)) == len(choice) for choice in itertools.product(*assignments))
            if len(known) > maximum or len(possible) < minimum or not possible_roles: continue
            certain = all(row.certain for row in members)
            if certain and not minimum <= len(known) <= maximum: continue
            rows.append(Row(owner, bindings, certain))
        complete = all(source.source_complete for source in sources)
        spec = {'op': 'group_by_owner', 'inputs': [source.spec for source in sources],
                'min': minimum, 'max': maximum, 'required_roles': list(roles), 'role_policy': policy}
        return Expr(spec, 'class_defs', rows,
                    [*(p for source in sources for p in source.profiles), profile('group_by_owner', len(incoming), rows, complete)],
                    set().union(*(source.sources for source in sources)), complete)

    def check_entity(self, actual, entity, binding=False):
        relation, source, local = entity
        assert actual['relation'] == relation and actual['source_index'] == source and actual['local_index'] == local
        for key, expected in self.entities[entity].items():
            # Binding ABI exposes entity attributes; has_local_definition is optional there.
            if binding and key == 'has_local_definition' and key not in actual: continue
            assert actual.get(key) == expected, (entity, key, actual.get(key), expected)
        if not binding:
            origin = self.dataset['sources'][source]
            for key in ('input_index', 'source_sha256', 'content_id', 'occurrence_id', 'logical_dex_id'):
                assert actual[key] == origin[key], (entity, key)
            assert actual['snapshot_id'] == self.dataset['snapshot_id']

    def verify(self, value, expression, options=None):
        from multisource import verify_metadata
        options = options or {}
        assert value['profile'] == 'dex-query-relational-v3'
        assert value['relation'] == expression.relation and value['counter_domain'] == 'scan_records'
        assert 'visited_methods' not in value and 'total_methods' not in value
        assert re.fullmatch(r'query:v3:[0-9a-f]{64}', value['query_id'])
        if (expression.spec == {'op': 'scan', 'relation': 'method_defs'}
                and options.get('intent', 'enumerate') == 'enumerate'
                and set(options) <= {'schema_version', 'relation', 'intent', 'max_results'}):
            assert value['query_id'] == scan_method_query_id(options.get('max_results', 4096))
        # Top-level conveniences create real graph nodes in this order. Keep the
        # original expression above for the narrowly scoped canonical-ID golden.
        expression = self.effective_root(expression, options)
        metadata = dict(value); metadata['profile'] = 'dex-query-method-v1'
        verify_metadata(self.dataset, metadata)
        assert value['execution_status'] == 'Complete'
        assert value['query_scope']['sources'] == sorted(expression.sources)
        assert value['query_scope']['complete'] is expression.source_complete
        for source in value['sources']: assert source['local_scope']['relation'] == expression.relation
        scanned = sum(p['total_rows'] for p in expression.profiles)
        assert value['total_rows'] == value['visited_rows'] == scanned
        rows = expression.rows
        identity = options.get('unique_by', 'entity')
        intent = options.get('intent', 'enumerate')
        if intent == 'unique': rows = distinct_rows(rows, identity)
        unknown = sum(not row.certain for row in rows)
        known = [row for row in rows if row.certain]
        identity_count = len({row_key(row, identity) for row in known})
        assert value['unknown_rows'] == unknown
        complete = expression.source_complete and not unknown
        assert value['coverage'] == ('Complete' if complete else 'Partial')
        if intent == 'enumerate': decision, reason = 'NotApplicable', 'UnknownAttribute' if unknown else 'None'
        elif intent == 'unique':
            if len(known) > 1: decision, reason = 'ProvenFalse', 'Ambiguous'
            elif complete: decision, reason = ('ProvenTrue', 'None') if known else ('ProvenFalse', 'NoMatch')
            else: decision, reason = 'Undetermined', 'UnknownAttribute' if unknown else 'SourceScopeIncomplete'
        elif intent == 'exists':
            if known: decision, reason = 'ProvenTrue', 'Witness'
            elif complete: decision, reason = 'ProvenFalse', 'NoMatch'
            else: decision, reason = 'Undetermined', 'UnknownAttribute' if unknown else 'SourceScopeIncomplete'
        else:
            assert intent == 'top_n'
            decision, reason = ('ProvenTrue', 'None') if complete else ('Undetermined', 'UnknownAttribute' if unknown else 'SourceScopeIncomplete')
        assert (value['decision'], value['reason']) == (decision, reason)
        if intent == 'top_n':
            order = options['order_by']; assert len(order) == 1 and order[0]['field'] == 'name'
            descending = order[0].get('direction', 'asc') == 'desc'
            known = sorted(known, key=lambda row: self.entities[row.entity]['name'], reverse=descending)[:options['max_results']]
            assert value['query_profile']['order_verified'] is complete
        elif intent == 'unique': known = known[:2]
        elif intent == 'exists': known = known[:1]
        else: assert len(known) <= options.get('max_results', 4096)
        graph = value['relation_profile']; actual_profiles = graph['operators']
        assert graph['unique_by'] == identity
        assert graph['identity_count'] == identity_count
        assert len({p['node_id'] for p in actual_profiles}) == len(actual_profiles)
        assert graph['root_node'] in {p['node_id'] for p in actual_profiles}
        root_profile = next(p for p in actual_profiles if p['node_id'] == graph['root_node'])
        assert root_profile['op'] == expression.spec['op']
        profile_fields = ('op', 'input_rows', 'output_rows', 'unknown_rows', 'visited_rows', 'total_rows', 'complete')
        signatures = lambda profiles: Counter(tuple(p[field] for field in profile_fields) for p in profiles)
        assert signatures(actual_profiles) == signatures(expression.profiles), (actual_profiles, expression.profiles)
        actual_rows = []
        operator_ids = {p['node_id'] for p in actual_profiles}
        for actual in value['candidates']:
            entity = (actual['relation'], actual['source_index'], actual['local_index'])
            assert entity in self.entities; self.check_entity(actual, entity)
            bindings = []
            for binding in actual['bindings']:
                key = (binding['relation'], binding['source_index'], binding['local_index'])
                assert key in self.entities; self.check_entity(binding, key, True)
                assert binding['label'] is None or isinstance(binding['label'], str)
                bindings.append((binding['label'], key))
            assert len(set(bindings)) == len(bindings)
            actual_row = Row(entity, tuple(bindings)); actual_rows.append(actual_row)
            evidence_entities = {entity, *(key for _, key in bindings)}
            assert actual['evidence']
            for witness in actual['evidence']:
                assert witness['operator_node'] in operator_ids
                proof = witness['entity']; proof_key = (proof['relation'], proof['source_index'], proof['local_index'])
                assert proof_key in evidence_entities and proof_key in self.entities
                assert type(witness['matched']) is bool
        assert Counter(row_key(row) for row in actual_rows) == Counter(row_key(row) for row in known), (actual_rows, known)
        if intent == 'top_n': assert [row_key(row) for row in actual_rows] == [row_key(row) for row in known]
        return value


def run(exe, root):
    source = root/'tests/fixtures/generated/definition_catalog/definitions.dex'
    minimal = root/'tests/fixtures/generated/minimal.dex'
    late = root/'tests/fixtures/generated/query-ir/late-better.dex'
    out = root/'docs/evidence/relational-query'/('run-'+str(time.time_ns())); out.mkdir(parents=True)
    binary = hashlib.sha256(exe.read_bytes()).hexdigest(); records = []; rejected = []

    def call(name, oracle, expression, *, code=0, **options):
        query = {'schema_version': 1, 'relation': expression.spec, 'intent': 'enumerate', 'max_results': 100, **options}
        path = out/(name+'.query.json'); path.write_text(json.dumps(query, indent=2), encoding='utf-8')
        command = [str(exe), 'query', str(oracle.paths[0]), '--query', str(path), '--json']
        for extra in oracle.paths[1:]: command += ['--source', str(extra)]
        if not oracle.dataset['scope_complete']: command.append('--scope-incomplete')
        p = subprocess.run(command, capture_output=True, timeout=30)
        (out/(name+'.stdout.json')).write_bytes(p.stdout); (out/(name+'.stderr.log')).write_bytes(p.stderr)
        records.append({'name': name, 'command': command, 'exit_code': p.returncode,
                        'stdout_sha256': hashlib.sha256(p.stdout).hexdigest()})
        (out/'commands.json').write_text(json.dumps(records, indent=2), encoding='utf-8')
        assert p.returncode == code, (name, p.returncode, p.stdout, p.stderr)
        value = json.loads(p.stdout)
        if code == 0: oracle.verify(value, expression, query)
        else:
            assert value['coverage'] == 'Partial' and value['decision'] == 'Undetermined' and not value['candidates']
        return value

    def reject(name, valid, oracle, expression, mutate, **options):
        forged = copy.deepcopy(valid); mutate(forged)
        try: oracle.verify(forged, expression, options)
        except (AssertionError, ValueError, KeyError): rejected.append(name)
        else: raise AssertionError('forged evidence accepted: '+name)

    o = Oracle(root, [source]); two = Oracle(root, [source, source])
    golden = o.scan('method_defs')
    golden_result = call('canonical-default-method-scan', o, golden, max_results=4096)
    reject('golden-query-id', golden_result, o, golden,
           lambda v: v.update(query_id='query:v3:'+'0'*64), max_results=4096)
    fields = o.scan(); shared = o.scan(where={'name': 'shared'}, select=lambda r: r['name'] == 'shared')
    one = o.scan(where={'owner': 'Lcatalog/Child;'}, select=lambda r: r['owner'] == 'Lcatalog/Child;')
    call('scan-fields', o, fields)
    filtered = o.filter(fields, {'name': 'shared'}, lambda r: r['name'] == 'shared')
    call('filter-fields', o, filtered)
    bag = o.union(fields, fields, semantics='bag'); result = call('union-bag', o, bag)
    reject('bag-delete-row', result, o, bag, lambda v: v['candidates'].pop())
    reject('bag-delete-row-and-partial', result, o, bag,
           lambda v: (v['candidates'].pop(), v.update(coverage='Partial')))
    set_union = o.union(fields, fields); set_result = call('union-set', o, set_union)
    assert result['query_id'] != set_result['query_id']
    call('root-set', o, bag, semantics='set')
    call('root-where', o, bag, where={'name': 'shared'})
    call('root-where-then-set', o, bag, where={'name': 'shared'}, semantics='set')
    call('distinct-entity', o, o.distinct(bag, 'entity'))
    call('distinct-tuple', o, o.distinct(bag))
    a = o.label(one, 'A'); b = o.label(one, 'B'); roles = o.union(a, b, semantics='bag')
    call('label-tuples', o, roles)
    call('label-entity-distinct', o, o.distinct(roles, 'entity'))
    call('label-tuple-distinct', o, o.distinct(roles))
    call('unique-duplicate-entity', o, o.union(one, one, semantics='bag'), intent='unique')
    unique = call('unique-labelled-entity', o, roles, intent='unique')
    tuples = call('unique-labelled-tuple', o, roles, intent='unique', unique_by='tuple')
    assert unique['query_id'] != tuples['query_id']
    member_group = o.group(o.label(o.scan('method_defs'), 'M'), o.label(fields, 'F'), roles=('M', 'F'))
    grouped = call('group-method-and-field', o, member_group)
    reject('group-delete-member', grouped, o, member_group,
           lambda v: v['candidates'][0].update(bindings=[b for b in v['candidates'][0]['bindings'] if b['relation'] != 'method_defs']))
    reject('group-wrong-role', grouped, o, member_group,
           lambda v: next(b for b in v['candidates'][0]['bindings'] if b['label'] is not None).update(label='invented'))
    shared_roles = o.group(a, b, minimum=1, maximum=1, roles=('A', 'B'), policy='shared')
    distinct_roles = o.group(a, b, minimum=1, maximum=1, roles=('A', 'B'), policy='distinct')
    s = call('group-shared-role', o, shared_roles); d = call('group-distinct-role-impossible', o, distinct_roles)
    assert s['query_id'] != d['query_id']
    base = o.scan(where={'owner': 'Lcatalog/Base;'}, select=lambda r: r['owner'] == 'Lcatalog/Base;')
    call('group-distinct-role-assignment', o, o.group(o.label(base, 'A'), o.label(base, 'B'),
                                                   minimum=2, maximum=2, roles=('A', 'B'), policy='distinct'))
    call('group-deduplicates-member-count', o, o.group(bag, maximum=2))
    first = o.scan(where={'owner': 'Lcatalog/Base;', 'name': 'shared'},
                   select=lambda r: r['owner'] == 'Lcatalog/Base;' and r['name'] == 'shared')
    second = o.scan(where={'name': 'instanceField'}, select=lambda r: r['name'] == 'instanceField')
    call('group-late-maximum-rejects', o, o.group(first, second, maximum=1))
    cap = o.group(fields, minimum=2, maximum=2)
    call('root-cap-does-not-truncate-input', o, cap, max_results=1)
    limited = call('intermediate-budget-fails', o, cap, max_results=1, max_intermediate_rows=2, code=3)
    assert limited['execution_status'] == 'BudgetExceeded'
    cross = two.group(two.scan()); cross_result = call('group-two-occurrences', two, cross)
    assert len(cross_result['candidates']) == 4
    reject('group-wrong-member-source', cross_result, two, cross,
           lambda v: v['candidates'][0]['bindings'][0].update(source_index=1-v['candidates'][0]['source_index']))
    reject('group-wrong-evidence-source', cross_result, two, cross,
           lambda v: v['candidates'][0]['evidence'][0]['entity'].update(source_index=1-v['candidates'][0]['source_index']))
    cross_roles = two.group(two.label(two.scan(sources=[0]), 'A'), two.label(two.scan(sources=[1]), 'B'), roles=('A', 'B'))
    call('roles-cannot-cross-occurrence', two, cross_roles)
    external = o.scan('field_refs', {'owner': 'Lexternal/External;'}, lambda r: r['owner'] == 'Lexternal/External;')
    uncertain = o.scan('field_refs', {'flags_contains': 8},
                       lambda r: None if r['access_flags'] is None else bool(r['access_flags'] & 8))
    call('unknown-retained-at-root', o, uncertain)
    call('unknown-bag-multiplicity', o, o.union(uncertain, uncertain, semantics='bag'))
    recovered = o.union(uncertain, external, identity='entity')
    call('true-union-resolves-unknown', o, recovered)
    call('true-union-resolves-unknown-reversed', o, o.union(external, uncertain, identity='entity'))
    call('false-filter-resolves-unknown', o, o.filter(uncertain, {'name': 'absent'}, lambda r: False))
    call('filter-keeps-unknown', o, o.filter(uncertain, {'owner': 'Lexternal/External;'}, lambda r: r['owner'] == 'Lexternal/External;'))
    # Equivalent matcher encodings must share a normalized graph ID.
    alias = o.scan(where={'name': {'op': 'exact', 'u16': [ord(c) for c in 'shared']}}, select=lambda r: r['name'] == 'shared')
    normal = call('canonical-name-value', o, shared); aliased = call('canonical-name-u16', o, alias)
    assert normal['query_id'] == aliased['query_id'] and normal['candidates'] == aliased['candidates']
    ranked = Oracle(root, [minimal, late])
    late_branch = ranked.union(ranked.scan('method_defs', sources=[0]), ranked.scan('method_defs', sources=[1]), semantics='bag')
    result = call('topn-late-branch', ranked, late_branch, intent='top_n', max_results=1,
                  order_by=[{'field': 'name', 'direction': 'desc'}])
    assert result['candidates'][0]['name'] == 'zzzzzz' and result['candidates'][0]['source_index'] == 1
    reject('method-reference-is-not-definition-ordinal', result, ranked, late_branch,
           lambda v: v['candidates'][0].update(reference_index=1), intent='top_n', max_results=1,
           order_by=[{'field': 'name', 'direction': 'desc'}])
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == binary
    summary = {'passed': len(records), 'failed': 0, 'forged_evidence_rejected': len(rejected),
               'rejected_controls': rejected, 'executable_sha256': binary,
               'source_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (source, minimal, late)},
               'raw_entities_and_owner_groups_verified': True, 'source_identity_hashes_recomputed': True,
               'operator_counters_checked': True, 'canonical_alias_and_separation_checked': True,
               'query_id_hash_recomputed': True, 'query_id_hash_scope': 'Default method scan only',
               'default_scan_method_golden': scan_method_query_id(),
               'scope': 'Authored scan/filter/union/distinct/label/owner-group cases; no join/expand, runtime binding, or performance claim',
               'evidence': str(out)}
    (out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n', encoding='utf-8')
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--exe', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True); args = parser.parse_args()
    print(json.dumps(run(args.exe.resolve(), args.root.resolve()), indent=2))
