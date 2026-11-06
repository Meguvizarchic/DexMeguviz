"""Fixed Gradle configuration-section checks; no dependency resolution performed."""
import argparse
from pathlib import Path
from verify_aar import check_runtime_report

parser=argparse.ArgumentParser()
parser.add_argument('--runtime-report',type=Path,required=True)
args=parser.parse_args()
actual=args.runtime_report.read_text(encoding='utf-8',errors='replace')
cases=[
 ('actual',actual,True),
 ('empty-section','releaseRuntimeClasspath - Resolved configuration\nNo dependencies\n\nBUILD SUCCESSFUL\n',True),
 ('other-empty-masks-target','releaseRuntimeClasspath - Resolved configuration\n\\--- org.example:runtime:1\n\notherClasspath - other\nNo dependencies\n',False),
 ('target-plus-no-dependencies','releaseRuntimeClasspath - Resolved configuration\nNo dependencies\n+--- org.example:runtime:1\n',False),
 ('other-empty-before-target','otherClasspath - other\nNo dependencies\n\nreleaseRuntimeClasspath - target\n+--- org.example:runtime:1\n',False),
 ('duplicate-target','releaseRuntimeClasspath - first\nNo dependencies\nreleaseRuntimeClasspath - second\nNo dependencies\n',False),
 ('target-missing','otherClasspath - other\nNo dependencies\n',False),
 ('failed-report','releaseRuntimeClasspath - target\nNo dependencies\nBUILD FAILED\n',False),
]
for name,text,expected in cases:
 try:check_runtime_report(text);actual=True
 except ValueError:actual=False
 if actual!=expected:raise SystemExit('unexpected runtime-section result: '+name)
 print(name,actual)
print('PASS',len(cases),'runtime report sections')
