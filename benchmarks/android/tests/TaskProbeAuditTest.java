import io.github.jichuo1.dexmeguviz.bench.TaskProbe;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class TaskProbeAuditTest {
    static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    static void await(CountDownLatch l)throws InterruptedException{if(!l.await(3,TimeUnit.SECONDS))throw new AssertionError("test synchronization timeout");}
    public static void main(String[] args)throws Exception {
        AtomicLong crossTicks=new AtomicLong(100_000_000L);AtomicInteger counts=new AtomicInteger();CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
        TaskProbe crossing=new TaskProbe(()->crossTicks.addAndGet(1_000_000L),()->{
            if(counts.incrementAndGet()==32){entered.countDown();if(!release.await(2,TimeUnit.SECONDS))throw new IOException("test release timeout");}
            return 100000L;
        },100);
        TaskProbe.Result<Integer> c=crossing.measure(m->{m.prepared();await(entered);m.firstAnswer();m.closing();new Thread(()->{try{Thread.sleep(150);}catch(InterruptedException e){Thread.currentThread().interrupt();}finally{crossTicks.addAndGet(150_000_000L);release.countDown();}}).start();return 1;});
        check(c.taskReturned&&c.samplerStopped,"crossing task finishes");
        check(c.samples.length==0&&c.rawSamples.length==1&&c.rawSamples[0].startNanos<c.finishNanos&&c.rawSamples[0].endNanos>c.finishNanos,"boundary sample preserved as raw only");
        check(c.activeMissedSlots==1&&!c.localSampleComplete&&c.observedIncrementalPeakPssBytes==-1,"only the pre-end scheduled boundary slot is missed");

        AtomicLong multiTicks=new AtomicLong(100_000_000L);AtomicInteger multiReads=new AtomicInteger();CountDownLatch secondEntered=new CountDownLatch(1),secondRelease=new CountDownLatch(1);
        TaskProbe partialPeak=new TaskProbe(()->multiTicks.addAndGet(1_000_000L),()->{
            if(multiReads.incrementAndGet()==33){secondEntered.countDown();if(!secondRelease.await(2,TimeUnit.SECONDS))throw new IOException("test release timeout");}
            return 100000L;
        },100);
        TaskProbe.Result<Integer> partial=partialPeak.measure(m->{m.prepared();await(secondEntered);m.firstAnswer();m.closing();new Thread(()->{try{Thread.sleep(150);}catch(InterruptedException e){Thread.currentThread().interrupt();}finally{multiTicks.addAndGet(150_000_000L);secondRelease.countDown();}}).start();return 1;});
        check(partial.samples.length>=1&&partial.rawSamples.length>partial.samples.length,"valid in-task reading followed by boundary crossing");
        check(partial.boundaryIncomplete&&!partial.localSampleComplete&&partial.observedIncrementalPeakPssBytes==-1,"boundary crossing cannot certify a partial peak");

        AtomicLong lateTicks=new AtomicLong(100_000_000L);AtomicInteger lateReads=new AtomicInteger(),samplerClockCalls=new AtomicInteger();CountDownLatch lateBlocked=new CountDownLatch(1),lateRelease=new CountDownLatch(1);
        TaskProbe.Clock lateClock=()->{
            if(Thread.currentThread().getName().equals("dexmeguviz-pss-sampler")&&lateReads.get()==32&&samplerClockCalls.incrementAndGet()==3){
                lateBlocked.countDown();try{lateRelease.await();}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}
            }
            return lateTicks.addAndGet(1_000_000L);
        };
        TaskProbe delayed=new TaskProbe(lateClock,()->{lateReads.incrementAndGet();return 100000L;},100);
        TaskProbe.Result<Integer> delayedResult=delayed.measure(m->{m.prepared();await(lateBlocked);lateTicks.addAndGet(40_000_000L);m.firstAnswer();m.closing();new Thread(()->{try{Thread.sleep(150);}catch(InterruptedException e){Thread.currentThread().interrupt();}finally{lateRelease.countDown();}}).start();return 1;});
        check(delayedResult.samples.length==1&&!delayedResult.boundaryIncomplete&&delayedResult.activeMissedSlots>0,"stop before overdue planned read counts all task slots");
        check(!delayedResult.localSampleComplete,"missing planned task samples cannot pass completeness");

        AtomicLong ticks=new AtomicLong(100_000_000L);AtomicInteger baselineCount=new AtomicInteger();
        TaskProbe baseline=new TaskProbe(()->ticks.addAndGet(1_000_000L),()->{if(baselineCount.incrementAndGet()==31)ticks.addAndGet(50_000_000L);return 100000L;},30);
        TaskProbe.Result<Integer> b=baseline.measure(m->{m.prepared();Thread.sleep(20);m.firstAnswer();m.closing();return 1;});
        check(b.taskReturned&&b.baseline.length==31&&b.baselineMissedSlots==0,"last baseline does not create a phantom next slot");

        AtomicBoolean failClock=new AtomicBoolean();TaskProbe clockFailure=new TaskProbe(()->failClock.get()?-1:System.nanoTime(),()->100000L,10);
        TaskProbe.Result<Object> f=clockFailure.measure(m->{m.prepared();failClock.set(true);throw new IOException("task failure");});
        check(!f.taskReturned&&"java.io.IOException".equals(f.failureClass)&&"java.lang.IllegalStateException".equals(f.coordinatorFailureClass)&&f.prepareNanos>=0,"task failure and coordinator clock failure retained separately");

        AtomicBoolean failReaderClock=new AtomicBoolean();AtomicInteger readerCalls=new AtomicInteger();CountDownLatch readerFailed=new CountDownLatch(1);
        TaskProbe dualFailure=new TaskProbe(()->failReaderClock.get()?-1:System.nanoTime(),()->{
            if(readerCalls.incrementAndGet()==32){failReaderClock.set(true);readerFailed.countDown();throw new IOException("reader failure");}
            return 100000L;
        },10);
        TaskProbe.Result<Integer> dual=dualFailure.measure(m->{m.prepared();await(readerFailed);return 1;});
        check("java.io.IOException".equals(dual.readerFailureClass)&&"java.lang.IllegalStateException".equals(dual.samplerFailureClass),"reader and sampler clock failures both retained");
        check(dual.rawSamples.length==1&&dual.rawSamples[0].endNanos==-1,"reader failure retained even when end clock fails");

        AtomicInteger reads=new AtomicInteger();CountDownLatch blocking=new CountDownLatch(1),unblock=new CountDownLatch(1);
        TaskProbe slow=new TaskProbe(System::nanoTime,()->{if(reads.incrementAndGet()==32){blocking.countDown();unblock.await();}return 100000L;},10);
        TaskProbe.Result<Object> t=slow.measure(m->{m.prepared();await(blocking);throw new IOException("task failure while sampler blocks");});
        try {
            check(!t.samplerStopped&&!t.localSampleComplete&&t.baseline.length==31,"timeout preserves completed baseline");
            check(t.rawSamples.length==1&&t.rawSamples[0].startNanos>=t.admissionNanos&&t.rawSamples[0].endNanos==-1&&t.rawSamples[0].pssBytes==-1,"timeout preserves in-flight scheduled sample");
            check("java.io.IOException".equals(t.failureClass)&&"sampler_did_not_stop".equals(t.samplerFailureClass)&&t.prepareNanos>=0,"timeout preserves task error and partial phase");
            boolean refused=false;try{slow.measure(m->1);}catch(IllegalStateException e){refused=true;}check(refused,"blocked sampler prevents overlapping reuse");
        } finally {unblock.countDown();}
        System.out.println("PASS boundary sample retention, clipped missed slots, baseline, separate failures and timeout evidence");
    }
}
