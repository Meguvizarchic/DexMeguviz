"""Recompute CLI SourceSet identities for authored raw DEX test inputs."""
from pathlib import Path
import sys

def project_root(root,generator):
    if root is not None:return root.resolve()
    for candidate in generator.resolve().parents:
        if (candidate/'tools/evidence_verifier/multisource.py').is_file():return candidate
    raise ValueError('project root required for independent SourceSet oracle')

def dataset(root,fixture,repeat=False,complete=True):
    root=Path(root).resolve();fixture=Path(fixture).resolve()
    sys.path.insert(0,str(root/'tools/evidence_verifier'))
    from multisource import load_source_set
    paths=[fixture,fixture] if repeat else [fixture]
    return load_source_set([{'path':str(path)} for path in paths],root,complete,root)

def verify(value,expected):
    assert value['snapshot_id']==expected['snapshot_id']
    assert value['scope_complete'] is expected['scope_complete']
    assert value['input_count']==len(expected['inputs']) and value['source_count']==len(expected['sources'])
    assert value['input_bytes']==sum(x['input_bytes'] for x in expected['inputs'])
    assert value['dex_bytes']==sum(x['source_bytes'] for x in expected['sources'])
    assert len(value['inputs'])==len(expected['inputs']) and len(value['sources'])==len(expected['sources'])
    for actual,reference in zip(value['inputs'],expected['inputs']):
        for key in ('input_index','slot_key','role','format','source_sha256','content_id','input_bytes','source_count','allow_no_dex','expected_digest_verified'):
            assert actual[key]==reference[key],('input',key)
    for actual,reference in zip(value['sources'],expected['sources']):
        for key in ('source_index','input_index','slot_key','role','source_sha256','source_bytes','archive_sha256','content_id','occurrence_id','logical_dex_id','counts'):
            assert actual[key]==reference[key],('source',key)
        assert actual['snapshot_id']==expected['snapshot_id']
        assert actual['archive_entry_name']==(reference['entry_name'] or '')
        assert actual['archive_entry_index']==reference['central_index']
        assert actual['dex_version']==int(reference['version'])
        assert actual['crc_verified'] is False

def verify_row(row,value,expected):
    source=row['source_index'];assert 0<=source<len(expected['sources'])
    reference=expected['sources'][source]
    for key in ('source_index','input_index','source_sha256','content_id','occurrence_id','logical_dex_id'):
        assert row[key]==reference[key],('candidate',key)
    assert row['snapshot_id']==expected['snapshot_id']==value['snapshot_id']
