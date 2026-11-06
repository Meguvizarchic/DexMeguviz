package io.github.jichuo1.dexmeguviz.bench;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Converts one measured task into an analyzer-compatible record without inventing caller facts. */
public final class ProbeRecordBridge {
    private static final int MAX_JSON_NODES=600000,MAX_DEPTH=32,MAX_STRING=1048576,MAX_TEXT_CHARS=4000000,MAX_JSON_CHARS=32000000;
    private static final String[] FACTS={"case","phase","triplet_id","backend","order_position","identity_sha256","backend_build_identity","status","correctness_passed","projection_sha256","environment_valid","exclusion_reason","counters","warm_query_samples_ms","foreground_frame_times_ms","foreground_capture_complete","execution_complete","warm_query_ms","post_close_residual_bytes"};
    private ProbeRecordBridge(){}
    /**
     * Facts are explicit caller observations, not independently authenticated here.
     * Missing facts are emitted as null and force complete=false; caller must preserve input stability.
     */
    public static Map<String,Object> record(TaskProbe.Result<?> result,Map<String,?> facts){
        Map<String,Object> in=new LinkedHashMap<>();Budget budget=new Budget();Set<Object> stack=Collections.newSetFromMap(new IdentityHashMap<Object,Boolean>());
        for(String key:FACTS)in.put(key,copy(facts==null?null:facts.get(key),0,budget,stack));
        TaskProbe.Sample[] baseline=result==null||result.baseline==null?null:result.baseline.clone();
        TaskProbe.Sample[] raw=result==null||result.rawSamples==null?null:result.rawSamples.clone();
        TaskProbe.Sample[] samples=result==null||result.samples==null?null:result.samples.clone();
        boolean captureOk=validCapture(result,baseline,raw,samples);
        boolean factsOk=validFacts(in);
        Map<String,Object> metrics=new LinkedHashMap<>();
        metrics.put("prepare_ms",result==null?null:millis(result.prepareNanos));
        metrics.put("first_answer_ms",result==null?null:millis(result.firstAnswerNanos));
        metrics.put("warm_query_ms",in.get("warm_query_ms"));
        metrics.put("full_task_ms",result==null?null:millisDifference(result.admissionNanos,result.finishNanos));
        metrics.put("close_ms",result==null?null:millis(result.closeNanos));
        metrics.put("observed_incremental_peak_pss_bytes",result==null||result.observedIncrementalPeakPssBytes<0?null:result.observedIncrementalPeakPssBytes);
        metrics.put("post_close_residual_bytes",in.get("post_close_residual_bytes"));
        Map<String,Object> row=new LinkedHashMap<>();
        for(String key:new String[]{"case","phase","triplet_id","backend","order_position","identity_sha256","backend_build_identity"})row.put(key,in.get(key));
        row.put("complete",captureOk&&factsOk&&Boolean.TRUE.equals(in.get("execution_complete")));
        for(String key:new String[]{"status","correctness_passed","projection_sha256"})row.put(key,in.get(key));
        row.put("metrics",metrics);row.put("counters",in.get("counters"));row.put("environment_valid",in.get("environment_valid"));row.put("exclusion_reason",in.get("exclusion_reason"));
        row.put("warm_query_samples_ms",in.get("warm_query_samples_ms"));row.put("foreground_frame_times_ms",in.get("foreground_frame_times_ms"));row.put("foreground_capture_complete",in.get("foreground_capture_complete"));
        Map<String,Object> evidence=new LinkedHashMap<>();evidence.put("capture_integrity_passed",captureOk);evidence.put("required_facts_present",factsOk);evidence.put("execution_complete_claim",in.get("execution_complete"));
        if(result!=null){
            evidence.put("task_invoked",result.taskInvoked);evidence.put("task_returned",result.taskReturned);evidence.put("sampler_stopped",result.samplerStopped);evidence.put("local_sample_complete",result.localSampleComplete);evidence.put("truncated",result.truncated);evidence.put("boundary_incomplete",result.boundaryIncomplete);
            evidence.put("task_or_collection_failure",result.failureClass);evidence.put("sampler_failure",result.samplerFailureClass);evidence.put("coordinator_failure",result.coordinatorFailureClass);evidence.put("reader_failure",result.readerFailureClass);
            evidence.put("admission_ns",result.admissionNanos);evidence.put("finish_ns",result.finishNanos);evidence.put("prepare_ns",result.prepareNanos);evidence.put("first_answer_ns",result.firstAnswerNanos);evidence.put("close_ns",result.closeNanos);evidence.put("baseline_pss_bytes",result.baselinePssBytes);evidence.put("peak_delta_pss_bytes",result.observedIncrementalPeakPssBytes);evidence.put("baseline_missed_slots",result.baselineMissedSlots);evidence.put("active_missed_slots",result.activeMissedSlots);
            evidence.put("baseline_samples",sampleMaps(baseline));evidence.put("task_samples",sampleMaps(samples));evidence.put("raw_task_samples",sampleMaps(raw));
        }
        row.put("probe_evidence",evidence);return row;
    }
    public static String jsonRecord(TaskProbe.Result<?> result,Map<String,?> facts){
        StringBuilder out=new StringBuilder();write(record(result,facts),out,0,new Budget(),Collections.newSetFromMap(new IdentityHashMap<Object,Boolean>()));if(out.length()>MAX_JSON_CHARS)throw new IllegalArgumentException("JSON output limit");return out.toString();
    }
    private static Double millis(long nanos){return nanos<0?null:nanos/1000000.0;}
    private static Double millisDifference(long start,long end){return start<0||end<start?null:(end-start)/1000000.0;}
    private static boolean hex64(Object o){return o instanceof String&&((String)o).matches("[0-9a-f]{64}");}
    private static boolean buildIdentityPresent(Object o){return (o instanceof String&&!((String)o).trim().isEmpty())||(o instanceof Map&&!((Map<?,?>)o).isEmpty());}
    private static boolean nonnegative(Object o){return o instanceof Number&&Double.isFinite(((Number)o).doubleValue())&&((Number)o).doubleValue()>=0;}
    private static boolean positive(Object o){return nonnegative(o)&&((Number)o).doubleValue()>0;}
    private static boolean integerRange(Object o,int lo,int hi){return (o instanceof Integer||o instanceof Long||o instanceof Short||o instanceof Byte)&&((Number)o).longValue()>=lo&&((Number)o).longValue()<=hi;}
    private static boolean validFacts(Map<String,Object> in){
        Object c=in.get("case"),p=in.get("phase"),b=in.get("backend"),status=in.get("status");
        if(!(c instanceof String)||!Arrays.asList("cold_adaptation","full_L0_hit","snapshot_warm_query","foreground_adaptation","persistent_fact_hit").contains(c)||!(p instanceof String)||!(p.equals("warmup")||p.equals("measured"))||!integerRange(in.get("triplet_id"),1,p.equals("warmup")?5:30)||!(b instanceof String)||!(b.equals("A")||b.equals("B")||b.equals("C"))||!integerRange(in.get("order_position"),1,3))return false;
        if(!hex64(in.get("identity_sha256"))||!buildIdentityPresent(in.get("backend_build_identity"))||!hex64(in.get("projection_sha256"))||!(status instanceof String)||((String)status).isEmpty()||!(in.get("correctness_passed") instanceof Boolean)||!(in.get("environment_valid") instanceof Boolean)||!(in.get("execution_complete") instanceof Boolean))return false;
        if(!nonnegative(in.get("warm_query_ms"))||!nonnegative(in.get("post_close_residual_bytes")))return false;
        if(c.equals("snapshot_warm_query")){
            Object x=in.get("warm_query_samples_ms");if(!(x instanceof List)||((List<?>)x).size()!=10)return false;
            double[] values=new double[10];for(int i=0;i<10;i++){Object v=((List<?>)x).get(i);if(!positive(v))return false;values[i]=((Number)v).doubleValue();}Arrays.sort(values);
            double median=(values[4]+values[5])/2,reported=((Number)in.get("warm_query_ms")).doubleValue();if(!Double.isFinite(median)||Math.abs(median-reported)>Math.max(1e-12,Math.abs(median)*1e-12))return false;
        }
        if(c.equals("foreground_adaptation")){
            Object x=in.get("foreground_frame_times_ms");if(!Boolean.TRUE.equals(in.get("foreground_capture_complete"))||!(x instanceof List)||((List<?>)x).size()<1000)return false;
            for(Object v:(List<?>)x)if(!positive(v))return false;
        }
        if(c.equals("full_L0_hit")){
            Object x=in.get("counters");if(!(x instanceof Map))return false;Map<?,?> counters=(Map<?,?>)x;
            for(String name:new String[]{"native_scan_load_count","whole_APK_hash_count","source_open_count","scan_count","index_build_count"})if(!integerRange(counters.get(name),0,0))return false;
        }
        return true;
    }
    private static boolean same(TaskProbe.Sample a,TaskProbe.Sample b){return a!=null&&b!=null&&a.scheduledNanos==b.scheduledNanos&&a.startNanos==b.startNanos&&a.endNanos==b.endNanos&&a.pssBytes==b.pssBytes;}
    private static boolean validCapture(TaskProbe.Result<?> r,TaskProbe.Sample[] base,TaskProbe.Sample[] raw,TaskProbe.Sample[] samples){
        if(r==null||!r.taskInvoked||!r.taskReturned||!r.samplerStopped||!r.localSampleComplete||r.truncated||r.boundaryIncomplete||r.failureClass!=null||r.samplerFailureClass!=null||r.coordinatorFailureClass!=null||r.readerFailureClass!=null||r.admissionNanos<0||r.finishNanos<=r.admissionNanos||r.baselineMissedSlots!=0||r.activeMissedSlots!=0||base==null||base.length!=31||raw==null||samples==null||samples.length==0||raw.length>20000)return false;
        long[] pss=new long[31];long prev=-1;for(int i=0;i<31;i++){
            TaskProbe.Sample x=base[i];if(x==null||x.scheduledNanos<0||x.startNanos<x.scheduledNanos||x.endNanos<x.startNanos||x.endNanos>r.admissionNanos||x.pssBytes<=0||(i>0&&(x.scheduledNanos-prev!=TaskProbe.INTERVAL_NANOS||x.startNanos<base[i-1].endNanos)))return false;
            prev=x.scheduledNanos;pss[i]=x.pssBytes;
        }
        Arrays.sort(pss);if(pss[15]!=r.baselinePssBytes)return false;
        long previous=-1,previousEnd=-1,max=0,seen=0;int j=0;
        for(TaskProbe.Sample x:raw){
            if(x==null||x.scheduledNanos<r.admissionNanos||x.startNanos<x.scheduledNanos||(previous>=0&&x.scheduledNanos<=previous)||(x.scheduledNanos-r.admissionNanos)%TaskProbe.INTERVAL_NANOS!=0)return false;
            if(x.endNanos<x.startNanos||x.pssBytes<=0||(previousEnd>=0&&x.startNanos<previousEnd))return false;
            previous=x.scheduledNanos;previousEnd=x.endNanos;
            if(x.scheduledNanos<r.finishNanos&&(x.startNanos>=r.finishNanos||x.endNanos<0||x.endNanos>r.finishNanos))return false;
            if(x.endNanos>=0&&x.endNanos<=r.finishNanos){
                if(x.endNanos<x.startNanos||x.pssBytes<=0||j>=samples.length||!same(x,samples[j++]))return false;
                if(x.scheduledNanos<r.finishNanos){seen++;max=Math.max(max,x.pssBytes);}
            }
        }
        if(j!=samples.length)return false;
        long duration=r.finishNanos-r.admissionNanos,expected=duration/TaskProbe.INTERVAL_NANOS+(duration%TaskProbe.INTERVAL_NANOS==0?0:1);
        if(seen!=expected||r.observedIncrementalPeakPssBytes!=Math.max(0,max-r.baselinePssBytes))return false;
        return r.prepareNanos>=0&&r.firstAnswerNanos>=r.prepareNanos&&r.firstAnswerNanos<=duration&&r.closeNanos>=0&&r.closeNanos<=duration-r.firstAnswerNanos;
    }
    private static List<Object> sampleMaps(TaskProbe.Sample[] samples){
        if(samples==null)return null;List<Object> out=new ArrayList<>(samples.length);for(TaskProbe.Sample s:samples){if(s==null){out.add(null);continue;}Map<String,Object> x=new LinkedHashMap<>();x.put("scheduled_ns",s.scheduledNanos);x.put("start_ns",s.startNanos);x.put("end_ns",s.endNanos);x.put("pss_bytes",s.pssBytes);out.add(x);}return out;
    }
    private static final class Budget {int nodes;long textChars;void node(int depth){if(depth>MAX_DEPTH||++nodes>MAX_JSON_NODES)throw new IllegalArgumentException("JSON value exceeds structural limit");}void text(String s){textChars+=s.length();if(textChars>MAX_TEXT_CHARS)throw new IllegalArgumentException("JSON text budget");}}
    private static Object copy(Object value,int depth,Budget budget,Set<Object> stack){
        budget.node(depth);if(value==null||value instanceof Boolean)return value;if(value instanceof String){if(((String)value).length()>MAX_STRING)throw new IllegalArgumentException("JSON string limit");checkText((String)value);budget.text((String)value);return value;}
        if(value instanceof Byte||value instanceof Short||value instanceof Integer||value instanceof Long)return value;
        if(value instanceof Float||value instanceof Double){if(!Double.isFinite(((Number)value).doubleValue()))throw new IllegalArgumentException("nonfinite JSON number");return value;}
        if(value instanceof Map){if(!stack.add(value))throw new IllegalArgumentException("cyclic JSON object");Map<String,Object> x=new LinkedHashMap<>();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet()){if(!(e.getKey() instanceof String))throw new IllegalArgumentException("JSON key must be string");String key=(String)e.getKey();checkText(key);budget.text(key);if(key.length()>MAX_STRING)throw new IllegalArgumentException("JSON key limit");x.put(key,copy(e.getValue(),depth+1,budget,stack));}stack.remove(value);return x;}
        if(value instanceof List){if(!stack.add(value))throw new IllegalArgumentException("cyclic JSON array");List<Object> x=new ArrayList<>();for(Object item:(List<?>)value)x.add(copy(item,depth+1,budget,stack));stack.remove(value);return x;}
        throw new IllegalArgumentException("unsupported JSON value");
    }
    private static void checkText(String text){for(int i=0;i<text.length();i++){char c=text.charAt(i);if(Character.isHighSurrogate(c)){if(++i>=text.length()||!Character.isLowSurrogate(text.charAt(i)))throw new IllegalArgumentException("unpaired UTF-16 surrogate");}else if(Character.isLowSurrogate(c))throw new IllegalArgumentException("unpaired UTF-16 surrogate");}}
    private static void write(Object value,StringBuilder out,int depth,Budget budget,Set<Object> stack){
        budget.node(depth);if(out.length()>MAX_JSON_CHARS)throw new IllegalArgumentException("JSON output limit");if(value==null){out.append("null");return;}if(value instanceof Boolean||value instanceof Number){out.append(value);return;}
        if(value instanceof String){String text=(String)value;checkText(text);budget.text(text);out.append('"');for(int i=0;i<text.length();i++){char c=text.charAt(i);switch(c){case '"':out.append("\\\"");break;case '\\':out.append("\\\\");break;case '\b':out.append("\\b");break;case '\f':out.append("\\f");break;case '\n':out.append("\\n");break;case '\r':out.append("\\r");break;case '\t':out.append("\\t");break;default:if(c<0x20)out.append(String.format("\\u%04x",(int)c));else out.append(c);}}out.append('"');return;}
        if(value instanceof Map){if(!stack.add(value))throw new IllegalArgumentException("cyclic JSON object");out.append('{');boolean first=true;for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet()){if(!first)out.append(',');first=false;write(e.getKey(),out,depth+1,budget,stack);out.append(':');write(e.getValue(),out,depth+1,budget,stack);}out.append('}');stack.remove(value);return;}
        if(value instanceof List){if(!stack.add(value))throw new IllegalArgumentException("cyclic JSON array");out.append('[');boolean first=true;for(Object x:(List<?>)value){if(!first)out.append(',');first=false;write(x,out,depth+1,budget,stack);}out.append(']');stack.remove(value);return;}throw new IllegalArgumentException("unsupported JSON value");
    }
}
