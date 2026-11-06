package io.github.jichuo1.dexmeguviz.bench;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

/** In-process measurement primitive. It does not establish task correctness or performance acceptance. */
public final class TaskProbe {
    public interface Clock { long nanos(); }
    /** Return positive bytes, or throw when unavailable. */
    public interface PssReader { long readBytes() throws Exception; }
    public interface Task<T> { T run(Markers markers) throws Exception; }
    public static final int BASELINE_COUNT=31;
    public static final long INTERVAL_NANOS=10_000_000L;
    private static final long START_TIMEOUT_MS=30000, STOP_TIMEOUT_MS=5000;
    private final Clock clock;
    private final PssReader reader;
    private final int maxSamples;
    private boolean busy;
    public TaskProbe(Clock clock,PssReader reader,int maxSamples) {
        if(clock==null || reader==null) throw new NullPointerException();
        if(maxSamples<1 || maxSamples>20000) throw new IllegalArgumentException("sample limit");
        this.clock=clock;this.reader=reader;this.maxSamples=maxSamples;
    }
    public static final class Markers {
        private final Clock clock;private final long start;private long prepared=-1,first=-1,closing=-1;
        private Markers(Clock c,long s){clock=c;start=s;}
        private long now(){long n=clock.nanos();if(n<start)throw new IllegalStateException("clock moved backwards");return n;}
        public synchronized void prepared(){if(prepared!=-1||first!=-1||closing!=-1)throw new IllegalStateException("prepared marker order");prepared=now();}
        public synchronized void firstAnswer(){if(prepared<0||first!=-1||closing!=-1)throw new IllegalStateException("first answer marker order");first=now();if(first<prepared)throw new IllegalStateException("clock moved backwards");}
        public synchronized void closing(){if(first<0||closing!=-1)throw new IllegalStateException("closing marker order");closing=now();if(closing<first)throw new IllegalStateException("clock moved backwards");}
        private synchronized long[] snapshot(){return new long[]{prepared,first,closing};}
    }
    public static final class Sample {
        public final long scheduledNanos,startNanos,endNanos,pssBytes;
        private Sample(long d,long s,long e,long p){scheduledNanos=d;startNanos=s;endNanos=e;pssBytes=p;}
    }
    public static final class Result<T> {
        public final boolean taskInvoked,taskReturned,samplerStopped,localSampleComplete,truncated,boundaryIncomplete;
        public final String failureClass,samplerFailureClass,coordinatorFailureClass,readerFailureClass;
        public final long admissionNanos,finishNanos,prepareNanos,firstAnswerNanos,closeNanos,baselinePssBytes,observedIncrementalPeakPssBytes,baselineMissedSlots,activeMissedSlots;
        /** samples are entirely in-task; rawSamples also retains boundary-crossing reads. */
        public final Sample[] baseline,samples,rawSamples;
        public final T value;
        private Result(boolean invoked,boolean returned,boolean stopped,boolean complete,boolean truncated,boolean boundaryIncomplete,String failure,String samplerFailure,String coordinatorFailure,String readerFailure,long start,long end,long prep,long first,long close,long base,long peak,long bm,long am,Sample[] before,Sample[] active,Sample[] raw,T value){
            taskInvoked=invoked;taskReturned=returned;samplerStopped=stopped;localSampleComplete=complete;this.truncated=truncated;this.boundaryIncomplete=boundaryIncomplete;failureClass=failure;samplerFailureClass=samplerFailure;coordinatorFailureClass=coordinatorFailure;readerFailureClass=readerFailure;admissionNanos=start;finishNanos=end;prepareNanos=prep;firstAnswerNanos=first;closeNanos=close;baselinePssBytes=base;observedIncrementalPeakPssBytes=peak;baselineMissedSlots=bm;activeMissedSlots=am;baseline=before;samples=active;rawSamples=raw;this.value=value;
        }
        public double fullTaskMillis(){return admissionNanos>=0&&finishNanos>=admissionNanos?(finishNanos-admissionNanos)/1_000_000.0:Double.NaN;}
    }
    private static final class Buffer {
        final long[] scheduled,start,end,pss,missedFirst,missedCount;int count,missedRanges;boolean truncated;String readerFailure;
        Buffer(int n){scheduled=new long[n];start=new long[n];end=new long[n];pss=new long[n];missedFirst=new long[n];missedCount=new long[n];}
        synchronized void record(int i,long due,long started,long ended,long value){scheduled[i]=due;start[i]=started;end[i]=ended;pss[i]=value;count=i+1;}
        synchronized void markTruncated(){truncated=true;}
        synchronized void markReaderFailure(Throwable failure){readerFailure=failure.getClass().getName();}
        synchronized boolean isTruncated(){return truncated;}
        synchronized void addMissed(long first,long n){
            if(missedRanges==missedFirst.length)throw new IllegalStateException("missed range limit");
            missedFirst[missedRanges]=first;missedCount[missedRanges]=n;missedRanges++;
        }
        /** Count skipped scheduled points strictly before the task's end; -1 means all. */
        synchronized long missedBefore(long deadline){
            long total=0;
            for(int i=0;i<missedRanges;i++){
                long n=missedCount[i];
                if(deadline>=0){if(missedFirst[i]>=deadline)continue;n=Math.min(n,1+(deadline-1-missedFirst[i])/INTERVAL_NANOS);}
                total=Math.addExact(total,n);
            }
            return total;
        }
        static final class Snapshot {
            final Sample[] raw,within;final long missed;final boolean truncated;final String readerFailure;
            Snapshot(Sample[] raw,Sample[] within,long missed,boolean truncated,String readerFailure){this.raw=raw;this.within=within;this.missed=missed;this.truncated=truncated;this.readerFailure=readerFailure;}
        }
        synchronized Snapshot snapshot(long deadline){
            Sample[] all=new Sample[count];int n=0;
            for(int i=0;i<count;i++){
                all[i]=new Sample(scheduled[i],start[i],end[i],pss[i]);
                if(deadline<0||(end[i]>=0&&end[i]<=deadline))n++;
            }
            Sample[] within=new Sample[n];int j=0;
            for(Sample sample:all)if(deadline<0||(sample.endNanos>=0&&sample.endNanos<=deadline))within[j++]=sample;
            return new Snapshot(all,within,missedBefore(deadline),truncated,readerFailure);
        }
    }
    private long now(){long n=clock.nanos();if(n<0)throw new IllegalStateException("negative monotonic clock");return n;}
    private void waitUntil(long deadline) throws InterruptedException {
        while(true){if(Thread.interrupted())throw new InterruptedException();long n=now();if(n>=deadline)return;LockSupport.parkNanos(deadline-n);}
    }
    private long advance(long deadline,Buffer b) {
        long next=Math.addExact(deadline,INTERVAL_NANOS);long n=now();
        if(n>=next){long missed=(n-next)/INTERVAL_NANOS+1;b.addMissed(next,missed);next=Math.addExact(next,Math.multiplyExact(missed,INTERVAL_NANOS));}return next;
    }
    private void sample(Buffer b,long deadline) throws Exception {
        if(b.count==b.pss.length){b.markTruncated();return;}
        int i=b.count;long start=now();
        if(start<deadline || (i>0 && start<b.end[i-1]))throw new IllegalStateException("clock moved backwards");
        // Publish the scheduled and start timestamps before a potentially blocking reader.
        // The -1 end/PSS sentinel means the read has not finished in this snapshot.
        b.record(i,deadline,start,-1,-1);
        long p;
        try { p=reader.readBytes(); if(p<=0)throw new IllegalStateException("PSS unavailable"); }
        catch(Exception | LinkageError e){b.markReaderFailure(e);long end=now();if(end>=start)b.record(i,deadline,start,end,-1);throw e;}
        long end=now();if(end<start)throw new IllegalStateException("clock moved backwards");
        b.record(i,deadline,start,end,p);
    }
    private static long phaseFromStart(long start,long end,long mark){
        return start>=0&&mark>=start&&(end<0||mark<=end)?mark-start:-1;
    }
    /** Count all scheduled task slots without assuming the worker ran before stop. */
    private static long missingActiveSlots(Sample[] within,long start,long end){
        if(start<0||end<start)return -1;
        long duration=end-start,expected=duration/INTERVAL_NANOS+(duration%INTERVAL_NANOS==0?0:1),seen=0,previous=-1;
        for(Sample sample:within){
            long due=sample.scheduledNanos;
            if(due<start||due>=end||sample.pssBytes<=0)continue;
            if((due-start)%INTERVAL_NANOS!=0||(previous>=0&&due<=previous))return -1;
            previous=due;seen++;
        }
        return seen<=expected?expected-seen:-1;
    }
    /** Caller invokes the complete task including synchronous cleanup in task.run. */
    public <T> Result<T> measure(Task<T> task) {
        if(task==null)throw new NullPointerException("task");
        synchronized(this){if(busy)throw new IllegalStateException("probe is busy");}
        Buffer before=new Buffer(BASELINE_COUNT),active=new Buffer(maxSamples);
        CountDownLatch ready=new CountDownLatch(1),go=new CountDownLatch(1);
        final class State {volatile boolean stop;boolean taskFinished,workerDone;volatile long start=-1,end=-1;volatile String error;}
        State state=new State();
        Thread worker=new Thread(()->{
            try {
                long due=now();for(int i=0;i<BASELINE_COUNT;i++){waitUntil(due);sample(before,due);if(i+1<BASELINE_COUNT)due=advance(due,before);}ready.countDown();
                go.await();if(state.stop)return;
                due=state.start;
                while(!state.stop){waitUntil(due);if(state.stop)break;sample(active,due);if(active.isTruncated())break;due=advance(due,active);}
            }catch(Exception e){state.error=e.getClass().getName();}catch(Error e){state.error=e.getClass().getName();throw e;}
            finally{ready.countDown();synchronized(TaskProbe.this){state.workerDone=true;if(state.taskFinished)busy=false;}}
        },"dexmeguviz-pss-sampler");worker.setDaemon(true);
        synchronized(this){if(busy)throw new IllegalStateException("probe is busy");busy=true;}
        try{worker.start();}catch(RuntimeException | Error e){synchronized(this){busy=false;}throw e;}
        boolean invoked=false,returned=false,stopped=false,interrupted=false;String failure=null,coordinatorFailure=null;T value=null;Markers markers=null;
        try {
            boolean baselineReady=ready.await(START_TIMEOUT_MS,TimeUnit.MILLISECONDS);
            if(!baselineReady||state.error!=null||before.count!=BASELINE_COUNT){failure=baselineReady?"baseline_failed:"+String.valueOf(state.error):"baseline_timeout";}
            else {state.start=now();markers=new Markers(clock,state.start);go.countDown();invoked=true;
                try{value=task.run(markers);returned=true;}catch(InterruptedException e){interrupted=true;failure=e.getClass().getName();}catch(Exception e){failure=e.getClass().getName();}catch(LinkageError | AssertionError e){failure=e.getClass().getName();}
                finally{state.end=now();}
            }
        }catch(InterruptedException e){interrupted=true;failure=e.getClass().getName();}
        catch(RuntimeException e){coordinatorFailure=e.getClass().getName();if(failure==null)failure=coordinatorFailure;}
        finally{state.stop=true;go.countDown();LockSupport.unpark(worker);try{worker.join(STOP_TIMEOUT_MS);}catch(InterruptedException e){interrupted=true;}stopped=!worker.isAlive();synchronized(this){state.taskFinished=true;if(state.workerDone)busy=false;}if(interrupted)Thread.currentThread().interrupt();}
        long[] phases=markers==null?new long[]{-1,-1,-1}:markers.snapshot();
        long prep=phaseFromStart(state.start,state.end,phases[0]);
        long first=phaseFromStart(state.start,state.end,phases[1]);
        long close=state.end>=0&&phases[2]>=state.start&&state.end>=phases[2]?state.end-phases[2]:-1;
        Buffer.Snapshot beforeSnapshot=before.snapshot(-1),activeSnapshot=active.snapshot(state.end);
        Sample[] baseline=beforeSnapshot.raw,raw=activeSnapshot.raw,samples=state.end>=0?activeSnapshot.within:new Sample[0];
        long baselineMissed=beforeSnapshot.missed,activeMissed=missingActiveSlots(samples,state.start,state.end);
        boolean truncated=activeSnapshot.truncated,boundaryIncomplete=false;
        if(state.end>=0)for(Sample sample:raw){
            if(sample.scheduledNanos<state.end&&(sample.startNanos>=state.end||sample.endNanos<0||sample.endNanos>state.end))boundaryIncomplete=true;
        }
        String readerFailure=beforeSnapshot.readerFailure!=null?beforeSnapshot.readerFailure:activeSnapshot.readerFailure;
        if(!stopped)return new Result<T>(invoked,returned,false,false,truncated,boundaryIncomplete,failure==null?"sampler_did_not_stop":failure,state.error==null?"sampler_did_not_stop":state.error,coordinatorFailure,readerFailure,state.start,state.end,prep,first,close,-1,-1,baselineMissed,activeMissed,baseline,samples,raw,value);
        long baselinePss=-1,peak=-1;if(baseline.length==BASELINE_COUNT){long[] vals=new long[BASELINE_COUNT];boolean valid=true;for(int i=0;i<vals.length;i++){vals[i]=baseline[i].pssBytes;if(vals[i]<=0)valid=false;}if(valid){Arrays.sort(vals);baselinePss=vals[15];}}
        if(baselinePss>0&&samples.length>0){boolean valid=true;long max=0;for(Sample x:samples){if(x.pssBytes<=0)valid=false;else max=Math.max(max,x.pssBytes);}if(valid)peak=Math.max(0,max-baselinePss);}
        if(boundaryIncomplete)peak=-1;
        boolean phasesOk=state.start>=0&&state.end>=state.start&&phases[0]>=state.start&&phases[1]>=phases[0]&&phases[2]>=phases[1]&&state.end>=phases[2];
        boolean complete=returned&&failure==null&&state.error==null&&!truncated&&!boundaryIncomplete&&baselineMissed==0&&activeMissed==0&&baselinePss>0&&peak>=0&&phasesOk;
        if(failure==null&&state.error!=null)failure="sampler:"+state.error;
        return new Result<T>(invoked,returned,true,complete,truncated,boundaryIncomplete,failure,state.error,coordinatorFailure,readerFailure,state.start,state.end,prep,first,close,baselinePss,peak,baselineMissed,activeMissed,baseline,samples,raw,value);
    }
}
