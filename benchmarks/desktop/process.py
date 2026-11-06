"""Bounded local CLI transport. No shell, cleanup or implicit command scripts."""
from __future__ import annotations
import json,os,queue,subprocess,threading,time
from pathlib import Path

class ProcessFailure(RuntimeError):pass

class Process:
    def __init__(self,argv:list[str],directory:Path,timeout_seconds:int):
        directory.mkdir(exist_ok=False);self.directory=directory;self.argv=argv;self.start_ns=time.perf_counter_ns();self.deadline=time.monotonic()+timeout_seconds
        self.lines=queue.Queue(maxsize=4);self.errors=[];self.exit_event=threading.Event();self.exit_ns=None;self.returncode=None
        flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
        self.child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=directory,creationflags=flags)
        self.readers=[threading.Thread(target=self._drain,args=(self.child.stdout,'stdout.bin',True,128<<20),daemon=True),threading.Thread(target=self._drain,args=(self.child.stderr,'stderr.bin',False,4<<20),daemon=True)]
        started=[]
        try:
            for thread in self.readers:thread.start();started.append(thread)
            self.watcher=threading.Thread(target=self._watch,daemon=True);self.watcher.start()
            threading.Thread(target=self._deadline,args=(timeout_seconds,),daemon=True).start()
        except BaseException:
            try:self.child.kill()
            except OSError:pass
            try:self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:pass
            for thread in started:thread.join(5)
            for stream in (self.child.stdin,self.child.stdout,self.child.stderr):
                try:stream.close()
                except (OSError,ValueError):pass
            raise
    def _deadline(self,seconds):
        if not self.exit_event.wait(seconds):self._fail("process timeout")
    def _fail(self,message):
        self.errors.append(message)
        try:self.child.kill()
        except OSError:pass
    def _watch(self):
        self.returncode=self.child.wait();self.exit_ns=time.perf_counter_ns();self.exit_event.set()
    def _put(self,item):
        try:self.lines.put(item,timeout=0.1)
        except queue.Full:raise ProcessFailure('unexpected stdout queue overflow')
    def _drain(self,stream,name,split,maximum):
        buffer=bytearray();total=0
        try:
            with (self.directory/name).open('xb') as output:
                while True:
                    chunk=stream.read1(65536)
                    if not chunk:break
                    remaining=maximum-total;output.write(chunk[:remaining]);total+=min(len(chunk),remaining)
                    if len(chunk)>remaining:raise ProcessFailure(name+' capture limit')
                    if split:
                        buffer.extend(chunk)
                        while b'\n' in buffer:
                            at=buffer.index(10);line=bytes(buffer[:at]);del buffer[:at+1]
                            if len(line)>8<<20:raise ProcessFailure('stdout line limit')
                            self._put((line,time.perf_counter_ns()))
                        if len(buffer)>8<<20:raise ProcessFailure('stdout line limit')
                if split and buffer:self._put((bytes(buffer),time.perf_counter_ns()))
                output.flush();os.fsync(output.fileno())
            if split:self._put((None,time.perf_counter_ns()))
        except Exception as error:self._fail(str(error))
        finally:stream.close()
    def remaining(self):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:self._fail('process timeout');raise ProcessFailure('process timeout')
        if self.errors:raise ProcessFailure('; '.join(self.errors))
        return remaining
    def send(self,value):
        raw=json.dumps(value,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')+b'\n'
        if len(raw)>65536:raise ProcessFailure('resident request line exceeds 65536 bytes')
        self.remaining()
        with (self.directory/'stdin.jsonl').open('ab') as log:log.write(raw);log.flush()
        try:self.child.stdin.write(raw);self.child.stdin.flush()
        except (OSError,ValueError) as error:raise ProcessFailure('stdin failed') from error
    def response(self):
        while True:
            try:line,stamp=self.lines.get(timeout=min(self.remaining(),0.1));break
            except queue.Empty:continue
        if line is None:raise ProcessFailure('unexpected stdout EOF')
        try:
            def unique(pairs):
                result={}
                for key,value in pairs:
                    if key in result:raise ValueError('duplicate response key')
                    result[key]=value
                return result
            result=json.loads(line.decode('utf-8'),object_pairs_hook=unique,parse_constant=lambda x:(_ for _ in ()).throw(ValueError(x)))
        except (ValueError,UnicodeError,RecursionError) as error:raise ProcessFailure('invalid JSON response') from error
        if not isinstance(result,dict):raise ProcessFailure('response must be an object')
        return result,stamp
    def finish(self):
        if self.child.stdin and not self.child.stdin.closed:
            try:self.child.stdin.close()
            except OSError:pass
        if not self.exit_event.wait(self.remaining()):self._fail('exit timeout');raise ProcessFailure('exit timeout')
        for thread in self.readers:
            thread.join(self.remaining())
            if thread.is_alive():self._fail('capture thread timeout');raise ProcessFailure('capture thread timeout')
        if self.errors:raise ProcessFailure('; '.join(self.errors))
        while not self.lines.empty():
            line,_=self.lines.get_nowait()
            if line is not None:raise ProcessFailure('extra stdout response')
        if self.returncode!=0:raise ProcessFailure('process exit '+str(self.returncode))
        return self.exit_ns-self.start_ns
    def abort(self):
        if self.child.poll() is None:
            try:self.child.kill()
            except OSError:pass
        self.exit_event.wait(5)
        for thread in self.readers:thread.join(5)
        if self.child.stdin and not self.child.stdin.closed:
            try:self.child.stdin.close()
            except OSError:pass
