import io.github.jichuo1.dexmeguviz.bench.TaskProbe;
import java.util.concurrent.atomic.AtomicInteger;
public final class TaskProbeTest {
  static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
  public static void main(String[] args){
    AtomicInteger count=new AtomicInteger();TaskProbe p=new TaskProbe(System::nanoTime,()->100000L+1000L*count.incrementAndGet(),1000);
    TaskProbe.Result<String> r=p.measure(m->{m.prepared();Thread.sleep(70);m.firstAnswer();m.closing();return "done";});
    check(r.taskInvoked&&r.taskReturned&&r.samplerStopped&&r.value.equals("done"),"run");
    check(r.baseline.length==31&&r.samples.length>0&&r.baselinePssBytes==116000L,"baseline and samples");
    check(r.observedIncrementalPeakPssBytes>0&&r.fullTaskMillis()>=60&&r.firstAnswerNanos>=r.prepareNanos,"metrics");
    for(TaskProbe.Sample s:r.samples)check(s.startNanos>=r.admissionNanos&&s.endNanos<=r.finishNanos,"sample interval");
    TaskProbe bad=new TaskProbe(System::nanoTime,()->{throw new IllegalStateException();},10);
    TaskProbe.Result<Object> b=bad.measure(m->{throw new AssertionError("must not run");});
    check(!b.taskInvoked&&!b.localSampleComplete&&b.failureClass!=null&&b.baseline.length==1&&b.baseline[0].pssBytes==-1,"baseline failure retains missing sample");
    AtomicInteger reads=new AtomicInteger();TaskProbe err=new TaskProbe(System::nanoTime,()->{if(reads.incrementAndGet()==32)throw new IllegalStateException();return 100000L;},10);
    TaskProbe.Result<Integer> e=err.measure(m->{m.prepared();Thread.sleep(50);m.firstAnswer();m.closing();return 1;});
    check(e.taskReturned&&!e.localSampleComplete&&e.failureClass!=null&&"java.lang.IllegalStateException".equals(e.samplerFailureClass)&&e.samples.length==1&&e.samples[0].pssBytes==-1&&e.observedIncrementalPeakPssBytes==-1,"active read failure retains missing sample and unavailable peak");
    TaskProbe throwing=new TaskProbe(System::nanoTime,()->50000L,10);
    TaskProbe.Result<Object> failed=throwing.measure(m->{m.prepared();throw new java.io.IOException("intentional");});
    check(failed.taskInvoked&&!failed.taskReturned&&!failed.localSampleComplete&&"java.io.IOException".equals(failed.failureClass)&&failed.prepareNanos>=0&&failed.firstAnswerNanos==-1,"task failure and partial marker retained");
    TaskProbe quiet=new TaskProbe(System::nanoTime,()->50000L,1);
    TaskProbe.Result<Integer> q=quiet.measure(m->{m.prepared();Thread.sleep(50);boolean refused=false;try{quiet.measure(x->0);}catch(IllegalStateException expected){refused=true;}check(refused,"no overlapping run");m.firstAnswer();m.closing();return 3;});
    check(q.taskReturned&&q.samplerStopped&&q.truncated&&!q.localSampleComplete,"truncation is never complete");
    System.out.println("PASS task timing/PSS sampling, baseline failure and concurrency/truncation controls");
  }
}
