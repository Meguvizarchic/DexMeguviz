import io.github.jichuo1.dexmeguviz.bench.TaskProbe;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
public final class TaskProbeStopRaceTest {
 public static void main(String[] args)throws Exception {
  AtomicLong ticks=new AtomicLong(100_000_000L);AtomicInteger reads=new AtomicInteger(),samplerCalls=new AtomicInteger();CountDownLatch waiting=new CountDownLatch(1),release=new CountDownLatch(1);
  TaskProbe.Clock clock=()->{if(Thread.currentThread().getName().equals("dexmeguviz-pss-sampler")&&reads.get()==32&&samplerCalls.incrementAndGet()==3){waiting.countDown();try{release.await();}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}}return ticks.addAndGet(1_000_000L);};
  TaskProbe probe=new TaskProbe(clock,()->{reads.incrementAndGet();return 100000L;},100);
  TaskProbe.Result<Integer> r=probe.measure(m->{m.prepared();if(!waiting.await(3,TimeUnit.SECONDS))throw new IllegalStateException("sampler did not wait");ticks.addAndGet(40_000_000L);m.firstAnswer();m.closing();new Thread(()->{try{Thread.sleep(150);}catch(InterruptedException e){Thread.currentThread().interrupt();}finally{release.countDown();}}).start();return 1;});
  if(r.samples.length!=1||r.boundaryIncomplete||r.activeMissedSlots<=0||r.localSampleComplete)throw new AssertionError("overdue task slots missed on stop: samples="+r.samples.length+", missed="+r.activeMissedSlots+", complete="+r.localSampleComplete);
  System.out.println("PASS delayed worker stop counts unobserved in-task sampling slots");
 }
}
