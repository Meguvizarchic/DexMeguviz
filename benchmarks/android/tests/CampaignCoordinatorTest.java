import io.github.jichuo1.dexmeguviz.bench.CampaignCoordinator;
import io.github.jichuo1.dexmeguviz.bench.CampaignJournal;
import io.github.jichuo1.dexmeguviz.bench.TaskProbe;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.*;

public final class CampaignCoordinatorTest {
 static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
 static String hex(byte[] x){StringBuilder b=new StringBuilder();for(byte z:x)b.append(String.format("%02x",z&255));return b.toString();}
 static final String EXPECTED=String.join("",Collections.nCopies(64,"a"));
 static String TEST_PROTOCOL;
 static CampaignCoordinator.Plan plan(String identity){return planWith(TEST_PROTOCOL,identity,CampaignCoordinator.registeredOrder(),false);}
 static CampaignCoordinator.Plan planWith(String protocol,String identity,String[] order,boolean legacy){
  Map<CampaignCoordinator.Variant,Object> builds=new EnumMap<>(CampaignCoordinator.Variant.class);
  for(CampaignCoordinator.Variant v:CampaignCoordinator.Variant.values())builds.put(v,"build-"+v.name());
  Map<String,String> projections=new LinkedHashMap<>();for(String s:new String[]{"cold_adaptation","full_L0_hit","snapshot_warm_query","foreground_adaptation"})projections.put(s,EXPECTED);
  return legacy?new CampaignCoordinator.Plan(identity,builds,projections,false):new CampaignCoordinator.Plan(protocol,identity,order,builds,projections,false);
 }
 static TaskProbe.Result<?> result(Object value)throws Exception{
  TaskProbe.Result<?> r=ProbeRecordBridgeTest.fixture(false,28500);Constructor<?> c=TaskProbe.Result.class.getDeclaredConstructors()[0];c.setAccessible(true);
  return (TaskProbe.Result<?>)c.newInstance(r.taskInvoked,r.taskReturned,r.samplerStopped,r.localSampleComplete,r.truncated,r.boundaryIncomplete,r.failureClass,r.samplerFailureClass,r.coordinatorFailureClass,r.readerFailureClass,r.admissionNanos,r.finishNanos,r.prepareNanos,r.firstAnswerNanos,r.closeNanos,r.baselinePssBytes,r.observedIncrementalPeakPssBytes,r.baselineMissedSlots,r.activeMissedSlots,r.baseline,r.samples,r.rawSamples,value);
 }
 static Map<String,Object> facts(CampaignCoordinator.Trial t){
  Map<String,Object> f=new LinkedHashMap<>();f.put("status","ok");f.put("execution_complete",true);f.put("correctness_passed",true);f.put("projection_sha256",EXPECTED);f.put("environment_valid",true);f.put("warm_query_ms",1.0);f.put("post_close_residual_bytes",0);
  Map<String,Object> counters=new LinkedHashMap<>();for(String n:new String[]{"native_scan_load_count","whole_APK_hash_count","source_open_count","scan_count","index_build_count"})counters.put(n,0);f.put("counters",counters);
  if(t.caseName.equals("snapshot_warm_query"))f.put("warm_query_samples_ms",Collections.nCopies(10,1.0));
  if(t.caseName.equals("foreground_adaptation")){f.put("foreground_frame_times_ms",Collections.nCopies(1000,16.0));f.put("foreground_capture_complete",true);}
  return f;
 }
 static final class FailingCloseChannel extends java.nio.channels.FileChannel {
  private final java.nio.channels.FileChannel inner;FailingCloseChannel(java.nio.channels.FileChannel inner){this.inner=inner;}
  protected void implCloseChannel()throws java.io.IOException{try{inner.close();}finally{throw new java.io.IOException("synthetic close failure");}}
  public int read(java.nio.ByteBuffer b)throws java.io.IOException{return inner.read(b);}public long read(java.nio.ByteBuffer[] b,int o,int n)throws java.io.IOException{return inner.read(b,o,n);}
  public int write(java.nio.ByteBuffer b)throws java.io.IOException{return inner.write(b);}public long write(java.nio.ByteBuffer[] b,int o,int n)throws java.io.IOException{return inner.write(b,o,n);}
  public long position()throws java.io.IOException{return inner.position();}public java.nio.channels.FileChannel position(long p)throws java.io.IOException{inner.position(p);return this;}
  public long size()throws java.io.IOException{return inner.size();}public java.nio.channels.FileChannel truncate(long n)throws java.io.IOException{inner.truncate(n);return this;}
  public void force(boolean m)throws java.io.IOException{inner.force(m);}public long transferTo(long p,long n,java.nio.channels.WritableByteChannel t)throws java.io.IOException{return inner.transferTo(p,n,t);}
  public long transferFrom(java.nio.channels.ReadableByteChannel s,long p,long n)throws java.io.IOException{return inner.transferFrom(s,p,n);}
  public int read(java.nio.ByteBuffer b,long p)throws java.io.IOException{return inner.read(b,p);}public int write(java.nio.ByteBuffer b,long p)throws java.io.IOException{return inner.write(b,p);}
  public java.nio.MappedByteBuffer map(MapMode m,long p,long n)throws java.io.IOException{return inner.map(m,p,n);}
  public java.nio.channels.FileLock lock(long p,long n,boolean s)throws java.io.IOException{return inner.lock(p,n,s);}
  public java.nio.channels.FileLock tryLock(long p,long n,boolean s)throws java.io.IOException{return inner.tryLock(p,n,s);}
 }
 static final class State {int calls,before,after,variantChecks,identityChecks;int badCorrectnessAt,badAfterAt,badBeforeAt,badReservedAt,changeIdentityAt,interruptAt,cycleAt,badProjectionAt,entryTrapAt;java.util.concurrent.CountDownLatch entered,release;final List<String> order=new ArrayList<>();}
 static List<CampaignCoordinator.Backend> backends(State state){
  List<CampaignCoordinator.Backend> out=new ArrayList<>();for(CampaignCoordinator.Variant v:CampaignCoordinator.Variant.values())out.add(new CampaignCoordinator.Backend(){
   public CampaignCoordinator.Variant variant(){state.variantChecks++;return v;}
   public Object buildIdentity(){state.identityChecks++;return state.changeIdentityAt>0&&state.calls>=state.changeIdentityAt?"changed-"+v.name():"build-"+v.name();}
   public Map<String,?> execute(CampaignCoordinator.Trial t,TaskProbe.Markers ignored)throws Exception{
    state.calls++;if(state.calls==state.interruptAt)throw new InterruptedException("synthetic");
    if(state.entered!=null&&state.calls==1){state.entered.countDown();if(!state.release.await(10,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("release timeout");}
    state.order.add(t.caseName+":"+t.phase+":"+t.tripletId+":"+t.orderPosition+":"+t.variant.name());Map<String,Object> f=facts(t);
    if(state.calls==state.badCorrectnessAt)f.put("correctness_passed",false);if(state.calls==state.badReservedAt)f.put("backend","X");if(state.calls==state.badProjectionAt)f.put("projection_sha256",String.join("",Collections.nCopies(64,"b")));
    if(state.calls==state.cycleAt){List<Object> cycle=new ArrayList<>();cycle.add(cycle);f.put("counters",cycle);}
    if(state.calls==state.entryTrapAt){List<Object> unused=new ArrayList<>();unused.add(unused);f.put("unknown_raw",unused);return new AbstractMap<String,Object>(){
     public Set<Map.Entry<String,Object>> entrySet(){throw new AssertionError("unknown keys must not be enumerated");}
     public boolean containsKey(Object key){return f.containsKey(key);}public Object get(Object key){return f.get(key);}
    };}return f;
   }
  });return out;
 }
 static CampaignCoordinator.Environment environment(State state){return new CampaignCoordinator.Environment(){
  public boolean before(CampaignCoordinator.Trial t){state.before++;return state.before!=state.badBeforeAt;}
  public boolean after(CampaignCoordinator.Trial t){state.after++;return state.after!=state.badAfterAt;}
 };}
 static CampaignCoordinator.Measurement fake(){return task->result(task.run(null));}
 static CampaignJournal journal(Path file,String protocol,String identity,byte[] id)throws Exception{return new CampaignJournal(file,"coordinator-test","synthetic_control",protocol,identity,id,120L*1024*1024);}
 static void rejectedBeforeBackend(CampaignJournal j,CampaignCoordinator.Plan p,State state,String label)throws Exception{
  boolean rejected=false;try{CampaignCoordinator.run(p,backends(state),environment(state),fake(),j);}catch(IllegalStateException expected){rejected=true;}
  check(rejected&&state.calls==0&&state.before==0&&state.after==0&&state.variantChecks==0&&state.identityChecks==0,label+" rejected before backend");
  boolean closed=false;try{j.finish("{}".getBytes(StandardCharsets.UTF_8));}catch(IllegalStateException expected){closed=true;}check(closed,label+" left incomplete/closed");
 }
 static void failure(Path file,String protocol,String identity,byte[] id,State state,int count,String label)throws Exception{
  CampaignJournal j=journal(file,protocol,identity,id);CampaignCoordinator.Result r=CampaignCoordinator.run(plan(identity),backends(state),environment(state),fake(),j);
  check(!r.allScheduledRecorded&&r.attemptsRecorded==count,label+" stopped");boolean closed=false;try{j.finish("{}".getBytes(StandardCharsets.UTF_8));}catch(IllegalStateException expected){closed=true;}check(closed,label+" journal closed without footer");
 }
 public static void main(String[] args)throws Exception{
  check(args.length==2,"arguments");Path dir=Paths.get(args[0]);String protocol=args[1];TEST_PROTOCOL=protocol;byte[] id="{\"unit\":true}".getBytes(StandardCharsets.UTF_8);String identity=hex(MessageDigest.getInstance("SHA-256").digest(id));
  String wrongDigest=String.join("",Collections.nCopies(64,"b"));
  rejectedBeforeBackend(journal(dir.resolve("protocol-mismatch.jsonl"),protocol,identity,id),planWith(wrongDigest,identity,CampaignCoordinator.registeredOrder(),false),new State(),"protocol mismatch");
  rejectedBeforeBackend(journal(dir.resolve("identity-mismatch.jsonl"),protocol,identity,id),planWith(protocol,wrongDigest,CampaignCoordinator.registeredOrder(),false),new State(),"identity mismatch");
  rejectedBeforeBackend(journal(dir.resolve("identity-bytes-mismatch.jsonl"),protocol,wrongDigest,id),planWith(protocol,wrongDigest,CampaignCoordinator.registeredOrder(),false),new State(),"identity byte hash mismatch");
  rejectedBeforeBackend(journal(dir.resolve("legacy-plan.jsonl"),protocol,identity,id),planWith(null,identity,null,true),new State(),"legacy unbound plan");
  String[] wrongOrder=CampaignCoordinator.registeredOrder();wrongOrder[0]="ABC";boolean orderRejected=false;try{planWith(protocol,identity,wrongOrder,false);}catch(IllegalArgumentException expected){orderRejected=true;}check(orderRejected,"declared order mismatch");
  CampaignJournal nonfresh=journal(dir.resolve("nonfresh.jsonl"),protocol,identity,id);nonfresh.append(null,Collections.emptyMap());rejectedBeforeBackend(nonfresh,plan(identity),new State(),"nonfresh journal");
  CampaignJournal moved=journal(dir.resolve("moved-position.jsonl"),protocol,identity,id);java.lang.reflect.Field channelPosition=CampaignJournal.class.getDeclaredField("channel");channelPosition.setAccessible(true);((java.nio.channels.FileChannel)channelPosition.get(moved)).position(0);rejectedBeforeBackend(moved,plan(identity),new State(),"changed journal position");
  CampaignJournal mismatchClose=journal(dir.resolve("mismatch-close.jsonl"),protocol,identity,id);java.lang.reflect.Field closeField=CampaignJournal.class.getDeclaredField("channel");closeField.setAccessible(true);closeField.set(mismatchClose,new FailingCloseChannel((java.nio.channels.FileChannel)closeField.get(mismatchClose)));
  State closeState=new State();boolean primary=false;try{CampaignCoordinator.run(planWith(wrongDigest,identity,CampaignCoordinator.registeredOrder(),false),backends(closeState),environment(closeState),fake(),mismatchClose);}catch(IllegalStateException e){primary=e.getMessage().contains("binding mismatch")&&e.getSuppressed().length==1&&e.getSuppressed()[0] instanceof java.io.IOException;}check(primary&&closeState.variantChecks==0,"preflight close does not mask mismatch");
  State claimed=new State();claimed.entered=new java.util.concurrent.CountDownLatch(1);claimed.release=new java.util.concurrent.CountDownLatch(1);claimed.badAfterAt=1;CampaignJournal claimedJournal=journal(dir.resolve("exclusive.jsonl"),protocol,identity,id);final CampaignCoordinator.Result[] claimedResult={null};final Throwable[] workerError={null};
  Thread worker=new Thread(()->{try{claimedResult[0]=CampaignCoordinator.run(plan(identity),backends(claimed),environment(claimed),fake(),claimedJournal);}catch(Throwable e){workerError[0]=e;}});worker.setDaemon(true);worker.start();
  try{
   check(claimed.entered.await(10,java.util.concurrent.TimeUnit.SECONDS),"backend entered");boolean denied=false;try{claimedJournal.append(null,Collections.emptyMap());}catch(IllegalStateException expected){denied=true;}check(denied,"external append denied");
   denied=false;try{claimedJournal.finish("{}".getBytes(StandardCharsets.UTF_8));}catch(IllegalStateException expected){denied=true;}check(denied,"external finish denied");
   denied=false;try{claimedJournal.close();}catch(IllegalStateException expected){denied=true;}check(denied,"external close denied");
   State contender=new State();denied=false;try{CampaignCoordinator.run(plan(identity),backends(contender),environment(contender),fake(),claimedJournal);}catch(IllegalStateException expected){denied=true;}check(denied&&contender.variantChecks==0,"second claimant did not invoke backend");
  }finally{claimed.release.countDown();}
  worker.join(10000);check(!worker.isAlive()&&workerError[0]==null&&claimedResult[0]!=null&&!claimedResult[0].allScheduledRecorded&&claimedResult[0].attemptsRecorded==1,"claim owner retained and closed");
  State success=new State();CampaignJournal j=journal(dir.resolve("complete.jsonl"),protocol,identity,id);CampaignCoordinator.Plan plan=plan(identity);
  CampaignCoordinator.Result r=CampaignCoordinator.run(plan,backends(success),environment(success),fake(),j);
  check(r.allScheduledRecorded&&r.attemptsRecorded==420&&success.calls==420&&success.before==420&&success.after==420,"all attempts");check(r.reason.equals("capture_complete_not_accepted"),"not acceptance");
  String[] order=CampaignCoordinator.registeredOrder();check(order.length==30,"schedule size");
  for(int i=0;i<105;i++){String phase=i<15?"warmup":"measured";int block=i<15?i/3:i/3-5;int pos=i%3;String got=success.order.get(i);String expected="cold_adaptation:"+phase+":"+(block+1)+":"+(pos+1)+":"+order[block].charAt(pos);check(got.equals(expected),"schedule "+i);}
  j.finish("{}".getBytes(StandardCharsets.UTF_8));
  State before=new State();before.badBeforeAt=1;failure(dir.resolve("before.jsonl"),protocol,identity,id,before,1,"before");check(before.calls==0&&before.after==0,"not invoked");
  State after=new State();after.badAfterAt=2;failure(dir.resolve("after.jsonl"),protocol,identity,id,after,2,"after");check(after.calls==2&&after.after==2,"after timing");
  State wrong=new State();wrong.badCorrectnessAt=3;failure(dir.resolve("incorrect.jsonl"),protocol,identity,id,wrong,3,"incorrect");check(wrong.calls==3,"stopped after incorrect");
  State projection=new State();projection.badProjectionAt=1;failure(dir.resolve("projection.jsonl"),protocol,identity,id,projection,1,"projection mismatch");
  State override=new State();override.badReservedAt=1;failure(dir.resolve("override.jsonl"),protocol,identity,id,override,1,"reserved");
  State identityChange=new State();identityChange.changeIdentityAt=1;failure(dir.resolve("identity.jsonl"),protocol,identity,id,identityChange,1,"identity drift");check(identityChange.after==1,"after even identity drift");
  State measureFailure=new State();CampaignJournal bad=journal(dir.resolve("measure.jsonl"),protocol,identity,id);CampaignCoordinator.Result x=CampaignCoordinator.run(plan(identity),backends(measureFailure),environment(measureFailure),task->{throw new IllegalStateException("synthetic");},bad);check(!x.allScheduledRecorded&&x.attemptsRecorded==1&&measureFailure.calls==0&&measureFailure.after==1,"measurement failure");
  State bounded=new State();bounded.entryTrapAt=1;bounded.badAfterAt=1;failure(dir.resolve("bounded-fields.jsonl"),protocol,identity,id,bounded,1,"bounded known fields");check(bounded.calls==1&&bounded.after==1,"unknown observation fields not enumerated");
  State serial=new State();serial.cycleAt=1;CampaignJournal serialJournal=journal(dir.resolve("serialization.jsonl"),protocol,identity,id);boolean serialFailure=false;
  try{CampaignCoordinator.run(plan(identity),backends(serial),environment(serial),fake(),serialJournal);}catch(IllegalArgumentException expected){serialFailure=true;}
  check(serialFailure&&serial.calls==1,"serialization failure stops");boolean serialClosed=false;try{serialJournal.finish("{}".getBytes(StandardCharsets.UTF_8));}catch(IllegalStateException expected){serialClosed=true;}check(serialClosed,"serialization failure cannot have footer");
  State dualState=new State();dualState.cycleAt=1;CampaignJournal dualJournal=journal(dir.resolve("dual-failure.jsonl"),protocol,identity,id);
  java.lang.reflect.Field channel=CampaignJournal.class.getDeclaredField("channel");channel.setAccessible(true);channel.set(dualJournal,new FailingCloseChannel((java.nio.channels.FileChannel)channel.get(dualJournal)));
  boolean primaryRetained=false;try{CampaignCoordinator.run(plan(identity),backends(dualState),environment(dualState),fake(),dualJournal);}catch(IllegalArgumentException expected){
   primaryRetained=expected.getSuppressed().length==1&&expected.getSuppressed()[0] instanceof java.io.IOException&&expected.getSuppressed()[0].getMessage().equals("synthetic close failure");
  }check(primaryRetained,"close failure must not mask serialization failure");
  State budgetState=new State();CampaignJournal budgetJournal=new CampaignJournal(dir.resolve("budget.jsonl"),"coordinator-test","synthetic_control",protocol,identity,id,4096);boolean budgetFailure=false;
  try{CampaignCoordinator.run(plan(identity),backends(budgetState),environment(budgetState),fake(),budgetJournal);}catch(java.io.IOException expected){budgetFailure=true;}
  check(budgetFailure&&budgetState.calls==1,"budget write failure stops");boolean budgetClosed=false;try{budgetJournal.finish("{}".getBytes(StandardCharsets.UTF_8));}catch(IllegalStateException expected){budgetClosed=true;}check(budgetClosed,"budget failure cannot have footer");
  State interruptedState=new State();CampaignJournal interruptedJournal=journal(dir.resolve("interrupted.jsonl"),protocol,identity,id);
  CampaignCoordinator.Environment interruptedEnv=new CampaignCoordinator.Environment(){public boolean before(CampaignCoordinator.Trial t)throws InterruptedException{throw new InterruptedException("synthetic");}public boolean after(CampaignCoordinator.Trial t){throw new AssertionError("after should not run");}};
  CampaignCoordinator.Result interruptedResult=CampaignCoordinator.run(plan(identity),backends(interruptedState),interruptedEnv,fake(),interruptedJournal);
  check(!interruptedResult.allScheduledRecorded&&interruptedResult.attemptsRecorded==1&&Thread.interrupted(),"interrupt recorded and restored");
  State taskInterrupted=new State();taskInterrupted.interruptAt=1;CampaignJournal taskInterruptedJournal=journal(dir.resolve("task-interrupted.jsonl"),protocol,identity,id);
  CampaignCoordinator.Result taskInterruptedResult=CampaignCoordinator.run(plan(identity),backends(taskInterrupted),environment(taskInterrupted),CampaignCoordinator.measureWith(new TaskProbe(System::nanoTime,()->120000L,64)),taskInterruptedJournal);
  check(!taskInterruptedResult.allScheduledRecorded&&taskInterruptedResult.attemptsRecorded==1&&taskInterrupted.calls==1&&taskInterrupted.after==1&&Thread.interrupted(),"task interruption recorded and restored");
  State real=new State();CampaignJournal actual=journal(dir.resolve("actual-probe.jsonl"),protocol,identity,id);CampaignCoordinator.Environment stopAfter=new CampaignCoordinator.Environment(){public boolean before(CampaignCoordinator.Trial t){return true;}public boolean after(CampaignCoordinator.Trial t){return false;}};
  CampaignCoordinator.Result realResult=CampaignCoordinator.run(plan(identity),backends(real),stopAfter,CampaignCoordinator.measureWith(new TaskProbe(System::nanoTime,()->120000L,64)),actual);
  check(!realResult.allScheduledRecorded&&realResult.attemptsRecorded==1&&real.calls==1,"real probe invocation");
  System.out.println("PASS 420 scheduled attempts, fail-closed stops, identity checks and real host probe invocation");
 }
}
