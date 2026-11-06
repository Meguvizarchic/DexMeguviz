"""Real-process opt-in background JSONL protocol; no device or network."""
import argparse,hashlib,importlib.util,json,os,queue,signal,sqlite3,subprocess,threading,time,uuid
from pathlib import Path
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,required=True);a=p.parse_args();root=a.root.resolve();dex=root/'tests/fixtures/generated/multisource/raw-a.dex'
spec=importlib.util.spec_from_file_location('raw_oracle',root/'tools/evidence_verifier/verify.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);parsed=mod.parse_dex(dex);defs=sorted(parsed['definitions'],key=lambda x:x['declaration_offset']);assert [(x['method_index'],x['name']) for x in defs]==[(2,'second'),(1,'locate')]
db=sqlite3.connect(':memory:');db.execute('CREATE TABLE mirror(ordinal INTEGER,name TEXT)');db.executemany('INSERT INTO mirror VALUES(?,?)',[(i,x['name']) for i,x in enumerate(defs)])
class Session:
 def __init__(self,fixture=dex):
  self.p=subprocess.Popen([str(a.exe),'--background',str(fixture)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.q=queue.Queue()
  def reader():
   try:
    for line in self.p.stdout:self.q.put(line)
   finally:self.q.put(None)
  self.reader=threading.Thread(target=reader,daemon=True);self.reader.start();ready=self.read();assert ready['op']=='ready' and ready['mode']=='background' and ready['source_scope']=='partial',ready
 def read(self):
  line=self.q.get(timeout=10);assert line is not None,('unexpected EOF',self.p.poll());return json.loads(line)
 def raw(self,b):self.p.stdin.write(b+b'\n');self.p.stdin.flush();return self.read()
 def cmd(self,op,**kwargs):return self.raw(json.dumps({'op':op,**kwargs},ensure_ascii=True,separators=(',',':')).encode())
 def wait(self,id):
  deadline=time.monotonic()+10
  while time.monotonic()<deadline:
   r=self.cmd('final',id=id)
   if r['status']==0:return r
   assert r['status']==5,r;time.sleep(.001)
  raise AssertionError('terminal timeout')
 def done(self,exit=0):
  self.p.stdin.close();assert self.p.wait(timeout=10)==exit,(self.p.returncode,self.p.stderr.read());self.reader.join(timeout=2);assert not self.reader.is_alive();extra=[]
  while not self.q.empty():
   line=self.q.get_nowait()
   if line is not None:extra.append(line)
  assert not extra,extra;return self.p.stderr.read()
 def abort(self):
  if self.p.poll() is None:self.p.kill();self.p.wait(timeout=10)
  if self.p.stdin and not self.p.stdin.closed:self.p.stdin.close()
s=Session()
try:
 assert s.cmd('run')['status']==21 and s.cmd('close')['status']==5
 for index in (0,1,99):
  sub=s.cmd('submit',sql='SELECT ordinal,name FROM dmg_method_defs WHERE ordinal=?1 ORDER BY ordinal',params=[{'integer':str(index)}],max_bytes=1024);assert sub['status']==0;id=sub['id'];f=s.wait(id)
  expected=[[{'integer':str(i)},name] for i,name in db.execute('SELECT ordinal,name FROM mirror WHERE ordinal=?',(index,))]
  assert f['execution_status']==0 and f['result']['rows']==expected and f['result']['source_scope']=='partial' and f['result']['snapshot_id']
  assert s.cmd('final',id=id)==f and s.cmd('ack',id=id)['status']==0 and s.cmd('final',id=id)['status']==12
 text='a\x00é😀';sub=s.cmd('submit',sql='SELECT ?1',params=[text],max_bytes=1024);f=s.wait(sub['id']);assert f['result']['rows']==[[text]];assert s.cmd('ack',id=sub['id'])['status']==0
 bad=s.cmd('submit',sql="SELECT CAST(X'EDA080' AS TEXT)",max_bytes=1024);id=bad['id'];deadline=time.monotonic()+10
 while True:
  f=s.cmd('final',id=id)
  if f['status']!=5:break
  assert time.monotonic()<deadline;time.sleep(.001)
 assert f['status']==20 and s.cmd('final',id=id)['status']==20 and s.cmd('stats')['terminal']==1 and s.cmd('ack',id=id)['status']==0
 # Admission bounds and result-budget errors must not erase terminals.
 assert s.cmd('submit',sql='SELECT ?1',params=[None]*257)['status']==21
 assert s.cmd('submit',sql='SELECT 1',max_bytes=(1<<20)+1)['status']==21
 budget=s.cmd('submit',sql='SELECT ?1',params=['x'],max_bytes=16);assert budget['status']==0
 f=s.wait(budget['id']);assert f['execution_status']==18 and f['result'] is None and s.cmd('final',id=budget['id'])==f
 assert s.cmd('ack',id=budget['id'])['status']==0
 assert s.raw(b'{"op":"stats","op":"stats"}')['status']==21
 assert s.raw(b'{"op":"stats","x":"\xff"}')['status']==21
 assert s.raw(b' '+b'x'*65536)['status']==18
 assert s.cmd('shutdown',cancel='yes')['status']==21
 assert s.cmd('shutdown',cancel=False)['status']==0 and s.cmd('submit',sql='SELECT 1')['status']==21
 assert s.cmd('close')['status']==0 and not s.done()
except BaseException:s.abort();raise
# A long executing request keeps the main thread responsive for queue/cancel.
s=Session()
try:
 long_sql='WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT count(*) FROM n'
 a1=s.cmd('submit',sql=long_sql,max_bytes=1024,max_progress=1000000);assert a1['status']==0;one=a1['id'];deadline=time.monotonic()+5
 while True:
  stats=s.cmd('stats')
  if stats['running']==1:break
  assert time.monotonic()<deadline,stats;time.sleep(.001)
 assert s.cmd('final',id=one)['status']==5 and s.cmd('ack',id=one)['status']==5
 a2=s.cmd('submit',sql='SELECT 22',max_bytes=1024);assert a2['status']==0;two=a2['id'];assert s.cmd('cancel',id=two)['status']==0
 assert s.wait(two)['execution_status']==9 and s.cmd('cancel',id=one)['status']==0
 assert s.wait(one)['execution_status']==9 and s.cmd('ack',id=one)['status']==0 and s.cmd('ack',id=two)['status']==0
 assert s.cmd('shutdown',cancel=False)['status']==0 and s.cmd('close')['status']==0 and not s.done()
except BaseException:s.abort();raise
# Draining preserves every terminal and reports capacity without silent eviction.
s=Session()
try:
 ids=[]
 for _ in range(16):
  r=s.cmd('submit',sql='SELECT 1',max_bytes=64);assert r['status']==0;ids.append(r['id'])
 assert s.cmd('submit',sql='SELECT 1',max_bytes=64)['status']==13
 assert s.cmd('shutdown',cancel=False)['status']==0 and s.cmd('close')['status']==5
 for id in ids:assert s.wait(id)['execution_status']==0 and s.cmd('ack',id=id)['status']==0
 assert s.cmd('stats')['terminal']==0 and s.cmd('close')['status']==0 and not s.done()
except BaseException:s.abort();raise
# Shutdown(true) retains cancellation terminals until acknowledgement.
s=Session()
try:
 ids=[s.cmd('submit',sql=long_sql,max_bytes=1024,max_progress=1000000)['id'],s.cmd('submit',sql='SELECT 2',max_bytes=1024)['id']]
 assert s.cmd('shutdown',cancel=True)['status']==0 and s.cmd('close')['status']==5
 for id in ids:assert s.wait(id)['execution_status']==9 and s.cmd('ack',id=id)['status']==0
 assert s.cmd('close')['status']==0 and not s.done()
except BaseException:s.abort();raise
# EOF with an accepted but unacknowledged record cannot report clean success.
s=Session()
try:
 assert s.cmd('submit',sql='SELECT 1',max_bytes=64)['status']==0
 assert b'unacknowledged' in s.done(2)
except BaseException:s.abort();raise
# Broken stdout is a transport failure; it is not a durable delivery channel.
read_fd,write_fd=os.pipe();os.close(read_fd)
p=subprocess.Popen([str(a.exe),'--background',str(dex)],stdin=subprocess.PIPE,stdout=write_fd,stderr=subprocess.PIPE);os.close(write_fd);p.stdin.close();rc=p.wait(timeout=10);assert rc==3 or (os.name!='nt' and rc==-signal.SIGPIPE),(rc,p.stderr.read())
# Deliver submit acknowledgement, then break the response transport. The
# process reports failure; the accepted but unacknowledged result is volatile.
p=subprocess.Popen([str(a.exe),'--background',str(dex)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
def read_one():
 q=queue.Queue();thread=threading.Thread(target=lambda:q.put(p.stdout.readline()),daemon=True);thread.start();line=q.get(timeout=10);thread.join(timeout=1);assert not thread.is_alive() and line;return json.loads(line)
try:
 assert read_one()['op']=='ready'
 p.stdin.write(b'{"op":"submit","sql":"SELECT 1","max_bytes":64}\n');p.stdin.flush();submitted=read_one();assert submitted['status']==0 and submitted['id']=='1'
 p.stdout.close();p.stdin.write(b'{"op":"stats"}\n');p.stdin.flush();p.stdin.close();rc=p.wait(timeout=10)
 assert rc==3 or (os.name!='nt' and rc==-signal.SIGPIPE),(rc,p.stderr.read())
finally:
 if p.poll() is None:p.kill();p.wait(timeout=10)
# Exercise the background argument's real Unicode path using the same bytes.
unicode_dir=a.exe.resolve().parent/('background-unicode-'+uuid.uuid4().hex);unicode_dir.mkdir();unicode_dex=unicode_dir/'中𠀀📂.dex'
with unicode_dex.open('xb') as f:f.write(dex.read_bytes())
assert hashlib.sha256(unicode_dex.read_bytes()).digest()==hashlib.sha256(dex.read_bytes()).digest()
s=Session(unicode_dex)
try:assert s.cmd('shutdown',cancel=False)['status']==0 and s.cmd('close')['status']==0 and not s.done()
except BaseException:s.abort();raise
db.close();print('PASS real background JSONL CLI, fixture oracle, quotas, cancellation, shutdown and transport',hashlib.sha256(dex.read_bytes()).hexdigest())
