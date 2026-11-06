"""Stable paired CLI routes; never invokes a shell or discovers an executable."""
from __future__ import annotations
import argparse,importlib.util,json,os,subprocess,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
NATIVE={'inspect','query','explain','sql'}
SCRIPTS={'diff':'cli/diff/dexdiff.py','verify':'tools/evidence_verifier/cli.py','precompute':'tools/precompute/package.py'}

def dispatch(argv=None):
    parser=argparse.ArgumentParser(description='DexMeguviz paired desktop commands. Put --native before the command; backend options follow it.')
    parser.add_argument('--native',type=Path,help='explicit trusted native CLI; required by inspect/query/explain/sql')
    parser.add_argument('--describe',action='store_true',help='show dispatch without executing a backend')
    parser.add_argument('command',choices=sorted(NATIVE|SCRIPTS.keys()))
    parser.add_argument('arguments',nargs=argparse.REMAINDER)
    args=parser.parse_args(argv)
    try:
        if args.command in NATIVE:
            if args.native is None:raise ValueError('this command requires --native PATH before the command')
            target=args.native.resolve(strict=True)
            if not target.is_file() or (os.name=='nt' and target.suffix.lower()!='.exe'):raise ValueError('native path must identify an executable file')
            command=[str(target),args.command,*args.arguments]
        else:
            if args.native is not None:raise ValueError('script commands take their own backend options, for example diff --exe PATH')
            target=(ROOT/SCRIPTS[args.command]).resolve(strict=True)
            if not target.is_relative_to(ROOT) or not target.is_file():raise ValueError('backend script outside installation')
            command=[sys.executable,'-B',str(target),*args.arguments]
        if args.describe:
            print(json.dumps({'schema_version':1,'command':args.command,'argv':command,'executed':False},ensure_ascii=True));return 0
        return subprocess.call(command)
    except (OSError,ValueError) as error:
        print(json.dumps({'status':'InvalidCommand','detail':str(error)},ensure_ascii=True),file=sys.stderr);return 2
    except KeyboardInterrupt:return 130

if __name__=='__main__':raise SystemExit(dispatch())
