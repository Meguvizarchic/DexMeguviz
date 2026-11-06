"""Do not persist environment-option values printed by Java launchers."""
import re

_BANNER=re.compile(rb'(?:NOTE:\s*)?Picked up (?:JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS)\s*:',re.I)
def redact_launcher(data):
    if isinstance(data,str):return redact_launcher(data.encode('utf-8')).decode('utf-8')
    return b''.join(b'[Java launcher environment options redacted]\n' if _BANNER.search(line) else line for line in data.splitlines(keepends=True))
