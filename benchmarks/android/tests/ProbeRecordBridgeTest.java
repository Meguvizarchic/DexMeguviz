import io.github.jichuo1.dexmeguviz.bench.ProbeRecordBridge;
import io.github.jichuo1.dexmeguviz.bench.TaskProbe;
import java.lang.reflect.Constructor;
import java.util.*;
public final class ProbeRecordBridgeTest {
 static void check(boolean x,String m){if(!x)throw new AssertionError(m);}
 static TaskProbe.Sample sample(long d,long st,long en,long p)throws Exception {Constructor<?> c=TaskProbe.Sample.class.getDeclaredConstructors()[0];c.setAccessible(true);return (TaskProbe.Sample)c.newInstance(d,st,en,p);}
 static TaskProbe.Result<?> fixture(boolean boundary,long peak)throws Exception {
  long start=1_310_000_000L;TaskProbe.Sample[] b=new TaskProbe.Sample[31],a=new TaskProbe.Sample[3];
  for(int i=0;i<31;i++){long d=1_000_000_000L+i*10_000_000L;b[i]=sample(d,d,d+1000,100000+i*100);}
  for(int i=0;i<3;i++){long d=start+i*10_000_000L;a[i]=sample(d,d,d+1000,110000+i*10000);}
  Constructor<?> c=TaskProbe.Result.class.getDeclaredConstructors()[0];c.setAccessible(true);
  return (TaskProbe.Result<?>)c.newInstance(true,true,true,true,false,boundary,null,null,null,null,start,start+30_000_000L,5_000_000L,15_000_000L,5_000_000L,101500L,peak,0L,0L,b,a,a,"ignored");
 }
 static Map<String,Object> facts(String id,String build,String projection){Map<String,Object> x=new LinkedHashMap<>();x.put("case","cold_adaptation");x.put("phase","measured");x.put("triplet_id",1);x.put("backend","A");x.put("order_position",2);x.put("identity_sha256",id);x.put("backend_build_identity",build);x.put("execution_complete",true);x.put("status","ok");x.put("correctness_passed",true);x.put("projection_sha256",projection);x.put("environment_valid",true);x.put("warm_query_ms",1.0);x.put("post_close_residual_bytes",0);return x;}
 public static void main(String[] args)throws Exception {
  String h=String.join("",Collections.nCopies(64,"a"));Map<String,Object> f=facts(h,"build",h);TaskProbe.Result<?> r=fixture(false,28500);
  if(args.length>0&&args[0].equals("emit")){System.out.print(ProbeRecordBridge.jsonRecord(r,facts(args[1],args[2],args[3])));return;}
  Map<String,Object> row=ProbeRecordBridge.record(r,f);check(Boolean.TRUE.equals(row.get("complete")),"valid explicit facts");String json=ProbeRecordBridge.jsonRecord(r,f);check(json.contains("\"complete\":true")&&json.contains("\"raw_task_samples\"")&&!json.contains("NaN"),"json evidence");
  Map<String,Object> missing=new LinkedHashMap<>(f);missing.remove("identity_sha256");row=ProbeRecordBridge.record(r,missing);check(Boolean.FALSE.equals(row.get("complete"))&&row.get("identity_sha256")==null,"missing identity");
  missing=new LinkedHashMap<>(f);missing.put("backend_build_identity",Collections.emptyMap());check(Boolean.FALSE.equals(ProbeRecordBridge.record(r,missing).get("complete")),"empty identity");
  missing=new LinkedHashMap<>(f);missing.remove("correctness_passed");check(Boolean.FALSE.equals(ProbeRecordBridge.record(r,missing).get("complete")),"correctness unknown");
  missing=new LinkedHashMap<>(f);missing.put("execution_complete",false);check(Boolean.FALSE.equals(ProbeRecordBridge.record(r,missing).get("complete")),"failed execution");
  check(Boolean.FALSE.equals(ProbeRecordBridge.record(fixture(true,28500),f).get("complete")),"boundary failure");
  check(Boolean.FALSE.equals(ProbeRecordBridge.record(fixture(false,-1),f).get("complete")),"missing peak");
  TaskProbe.Result<?> corrupted=fixture(false,28500);corrupted.rawSamples[0]=null;check(Boolean.FALSE.equals(ProbeRecordBridge.record(corrupted,f).get("complete")),"tampered samples");
  Map<String,Object> l0=new LinkedHashMap<>(f);l0.put("case","full_L0_hit");check(Boolean.FALSE.equals(ProbeRecordBridge.record(r,l0).get("complete")),"missing L0 counters");
  Map<String,Object> counters=new LinkedHashMap<>();for(String n:new String[]{"native_scan_load_count","whole_APK_hash_count","source_open_count","scan_count","index_build_count"})counters.put(n,0);l0.put("counters",counters);check(Boolean.TRUE.equals(ProbeRecordBridge.record(r,l0).get("complete")),"explicit L0 counters");
  Map<String,Object> warm=new LinkedHashMap<>(f);warm.put("case","snapshot_warm_query");warm.put("warm_query_samples_ms",Arrays.asList(1.,2.,3.,4.,5.,6.,7.,8.,9.,10.));warm.put("warm_query_ms",5.5);check(Boolean.TRUE.equals(ProbeRecordBridge.record(r,warm).get("complete")),"warm median");warm.put("warm_query_ms",5.);check(Boolean.FALSE.equals(ProbeRecordBridge.record(r,warm).get("complete")),"wrong warm median");
  Map<String,Object> fg=new LinkedHashMap<>(f);fg.put("case","foreground_adaptation");fg.put("foreground_capture_complete",true);fg.put("foreground_frame_times_ms",Collections.nCopies(999,16.));check(Boolean.FALSE.equals(ProbeRecordBridge.record(r,fg).get("complete")),"short frame capture");fg.put("foreground_frame_times_ms",Collections.nCopies(1000,16.));check(Boolean.TRUE.equals(ProbeRecordBridge.record(r,fg).get("complete")),"complete frame capture");
  check(Boolean.FALSE.equals(ProbeRecordBridge.record(null,f).get("complete")),"missing capture");
  Map<String,Object> weird=new LinkedHashMap<>(f);weird.put("backend_build_identity",Collections.singletonMap("name","\\\"\n雪"));check(ProbeRecordBridge.jsonRecord(r,weird).contains("\\\\\\\"\\n雪"),"unicode escape");
  List<Object> cycle=new ArrayList<>();cycle.add(cycle);weird.put("counters",cycle);boolean refused=false;try{ProbeRecordBridge.record(r,weird);}catch(IllegalArgumentException e){refused=true;}check(refused,"cyclic data rejected");
  System.out.println("PASS explicit facts, raw evidence, failure, corruption, warm, L0 and frame controls");
 }
}
