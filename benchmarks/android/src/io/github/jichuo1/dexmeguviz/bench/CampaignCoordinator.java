package io.github.jichuo1.dexmeguviz.bench;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Serial capture orchestration only; no backend, origin, or acceptance is authenticated here. */
public final class CampaignCoordinator {
    public enum Variant { A, B, C }
    private static final String[] ORDER={"BAC","ACB","CAB","ABC","BAC","BAC","ACB","BAC","ACB","CBA","BCA","CAB","BCA","ABC","CBA","CAB","CAB","CBA","ABC","CBA","ABC","BAC","CBA","ABC","BCA","CAB","BCA","ACB","ACB","BCA"};
    private static final String[] CASES={"cold_adaptation","full_L0_hit","snapshot_warm_query","foreground_adaptation"};
    private static final String[] OBSERVATION_FIELDS={"status","execution_complete","correctness_passed","projection_sha256","environment_valid","exclusion_reason","counters","warm_query_ms","warm_query_samples_ms","foreground_frame_times_ms","foreground_capture_complete","post_close_residual_bytes"};
    private CampaignCoordinator(){}

    /** The backend must complete the entire task and synchronous cleanup before it returns. */
    public interface Backend {
        Variant variant();
        Object buildIdentity();
        Map<String,?> execute(Trial trial,TaskProbe.Markers markers) throws Exception;
    }
    /** Each method is a caller assertion; false or an exception stops capture. */
    public interface Environment {
        boolean before(Trial trial) throws Exception;
        boolean after(Trial trial) throws Exception;
    }
    /** Allows deterministic host controls; production callers may use measureWith(probe). */
    public interface Measurement {
        TaskProbe.Result<?> measure(TaskProbe.Task<Map<String,?>> task) throws Exception;
    }
    public static Measurement measureWith(TaskProbe probe){
        if(probe==null)throw new NullPointerException("probe is required");
        return task->probe.measure(task);
    }
    public static final class Trial {
        public final String caseName,phase;
        public final int tripletId,orderPosition;
        public final Variant variant;
        private Trial(String c,String p,int id,int position,Variant v){caseName=c;phase=p;tripletId=id;orderPosition=position;variant=v;}
    }
    /** Fixed inputs are copied, but supplied hashes and identities are not independently authenticated. */
    public static final class Plan {
        public final String protocolSha256,identitySha256;
        private final Map<Variant,Object> builds;
        private final Map<String,String> projections;
        private final List<String> cases;
        /** Legacy constructor retains its JVM descriptor but does not authorize capture. */
        public Plan(String identitySha256,Map<Variant,?> backendBuilds,Map<String,String> expectedProjections,boolean persistentFacts){
            this(null,identitySha256,null,backendBuilds,expectedProjections,persistentFacts,true);
        }
        /** declaredOrder must be read and checked from the caller's frozen protocol. */
        public Plan(String protocolSha256,String identitySha256,String[] declaredOrder,Map<Variant,?> backendBuilds,Map<String,String> expectedProjections,boolean persistentFacts){
            this(protocolSha256,identitySha256,declaredOrder,backendBuilds,expectedProjections,persistentFacts,false);
        }
        private Plan(String protocolSha256,String identitySha256,String[] declaredOrder,Map<Variant,?> backendBuilds,Map<String,String> expectedProjections,boolean persistentFacts,boolean legacy){
            if(!legacy&&(!hex(protocolSha256)||declaredOrder==null||!Arrays.equals(ORDER,declaredOrder.clone())))throw new IllegalArgumentException("protocol digest and declared order required");
            if(!hex(identitySha256)||backendBuilds==null||expectedProjections==null)throw new IllegalArgumentException("identity and expectations required");
            if(backendBuilds.size()!=3)throw new IllegalArgumentException("three backend builds required");
            EnumMap<Variant,Object> built=new EnumMap<>(Variant.class);
            for(Variant v:Variant.values()){
                Object id=copyIdentity(backendBuilds.get(v));if(!identityPresent(id))throw new IllegalArgumentException("backend identity missing");built.put(v,id);
            }
            List<String> selected=new ArrayList<>();Collections.addAll(selected,CASES);if(persistentFacts)selected.add("persistent_fact_hit");
            if(expectedProjections.size()!=selected.size()||!expectedProjections.keySet().equals(new HashSet<>(selected)))throw new IllegalArgumentException("case projections mismatch");
            Map<String,String> projected=new LinkedHashMap<>();for(String name:selected){String x=expectedProjections.get(name);if(!hex(x))throw new IllegalArgumentException("invalid projection hash");projected.put(name,x);}
            this.protocolSha256=protocolSha256;this.identitySha256=identitySha256;this.builds=Collections.unmodifiableMap(built);this.projections=Collections.unmodifiableMap(projected);this.cases=Collections.unmodifiableList(selected);
        }
        public List<String> cases(){return cases;}
    }
    public static final class Result {
        /** True means all requested attempts were recorded; it is not an acceptance decision. */
        public final boolean allScheduledRecorded;
        public final int attemptsRecorded;
        public final String reason;
        private Result(boolean complete,int attempts,String reason){allScheduledRecorded=complete;attemptsRecorded=attempts;this.reason=reason;}
    }
    public static String[] registeredOrder(){return ORDER.clone();}
    private static boolean hex(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    private static boolean identityPresent(Object value){return (value instanceof String&&!((String)value).trim().isEmpty())||(value instanceof Map&&!((Map<?,?>)value).isEmpty());}
    private static Object copyIdentity(Object value){Map<String,Object> facts=new HashMap<>();facts.put("backend_build_identity",value);return ProbeRecordBridge.record(null,facts).get("backend_build_identity");}
    private static EnumMap<Variant,Backend> backends(Plan plan,List<? extends Backend> values){
        if(values==null||values.size()!=3)throw new IllegalArgumentException("three backends required");
        EnumMap<Variant,Backend> out=new EnumMap<>(Variant.class);
        for(Backend value:values){if(value==null)throw new NullPointerException("backend is required");Variant v=value.variant();
            if(v==null||out.put(v,value)!=null||!Objects.equals(copyIdentity(value.buildIdentity()),plan.builds.get(v)))throw new IllegalArgumentException("backend variant or identity mismatch");}
        if(out.size()!=3)throw new IllegalArgumentException("three unique variants required");return out;
    }
    private static Map<String,Object> base(Plan plan,Trial trial){
        Map<String,Object> facts=new LinkedHashMap<>();facts.put("case",trial.caseName);facts.put("phase",trial.phase);facts.put("triplet_id",trial.tripletId);facts.put("backend",trial.variant.name());facts.put("order_position",trial.orderPosition);facts.put("identity_sha256",plan.identitySha256);facts.put("backend_build_identity",plan.builds.get(trial.variant));return facts;
    }
    private static String error(String where,Throwable value){return where+":"+value.getClass().getName();}
    private static void markEnvironmentFailure(Map<String,Object> facts,String reason){
        facts.put("environment_valid",false);Object old=facts.get("exclusion_reason");
        if(old==null)facts.put("exclusion_reason",reason);else if(old instanceof String&&((String)old).length()<=4096-reason.length()-1)facts.put("exclusion_reason",old+";"+reason);
    }
    private static boolean identityMatches(Plan plan,Variant variant,Backend backend){return backend.variant()==variant&&Objects.equals(copyIdentity(backend.buildIdentity()),plan.builds.get(variant));}
    /** FileChannel closes on an already-interrupted thread; preserve the flag around journaling. */
    private static void appendPreservingInterrupt(CampaignJournal journal,Object token,TaskProbe.Result<?> result,Map<String,?> facts)throws IOException {
        boolean interrupted=Thread.interrupted();try{journal.appendClaimed(token,result,facts);}finally{if(interrupted)Thread.currentThread().interrupt();}
    }
    private static boolean acceptedForContinuing(Map<String,Object> row,String expected){
        return Boolean.TRUE.equals(row.get("complete"))&&"ok".equals(row.get("status"))&&Boolean.TRUE.equals(row.get("correctness_passed"))&&
            Boolean.TRUE.equals(row.get("environment_valid"))&&row.get("exclusion_reason")==null&&expected.equals(row.get("projection_sha256"));
    }
    /**
     * Writes every attempted member before proceeding. Failure closes the journal without a footer;
     * on complete capture the caller owns the still-open journal and must attach external gate evidence.
     */
    public static Result run(Plan plan,List<? extends Backend> supplied,Environment environment,Measurement measurement,CampaignJournal journal) throws IOException {
        if(plan==null||environment==null||measurement==null||journal==null)throw new NullPointerException("plan, environment, measurement and journal are required");
        int attempts=0;boolean complete=false;Throwable pending=null;Object token=null;
        try {
            // Check before even querying a backend for its variant or build identity.
            token=journal.claimFresh(plan.protocolSha256,plan.identitySha256);
            EnumMap<Variant,Backend> selected=backends(plan,supplied);
            for(String caseName:plan.cases)for(int phaseIndex=0;phaseIndex<2;phaseIndex++){
                String phase=phaseIndex==0?"warmup":"measured";int count=phaseIndex==0?5:30;
                for(int triplet=1;triplet<=count;triplet++){
                    String order=ORDER[triplet-1];
                    for(int position=1;position<=3;position++){
                        Variant variant=Variant.valueOf(order.substring(position-1,position));Trial trial=new Trial(caseName,phase,triplet,position,variant);Backend backend=selected.get(variant);Map<String,Object> facts=base(plan,trial);String preFailure=null;
                        try{if(!identityMatches(plan,variant,backend))preFailure="backend_identity_changed";}
                        catch(Exception | LinkageError e){preFailure=error("backend_identity_error",e);}
                        if(preFailure==null)try{if(!environment.before(trial))preFailure="environment_before_rejected";}
                        catch(InterruptedException e){Thread.currentThread().interrupt();preFailure=error("environment_before_error",e);}
                        catch(Exception | LinkageError e){preFailure=error("environment_before_error",e);}
                        if(preFailure!=null){facts.put("status","not_invoked");facts.put("execution_complete",false);markEnvironmentFailure(facts,preFailure);appendPreservingInterrupt(journal,token,null,facts);attempts++;return new Result(false,attempts,preFailure);}
                        TaskProbe.Result<?> measured=null;String measurementFailure=null;
                        try{measured=measurement.measure(markers->backend.execute(trial,markers));}
                        catch(InterruptedException e){Thread.currentThread().interrupt();measurementFailure=error("measurement_error",e);}
                        catch(Exception | LinkageError e){measurementFailure=error("measurement_error",e);}
                        if(measured!=null&&measured.value instanceof Map){
                            Map<?,?> observation=(Map<?,?>)measured.value;Map<String,Object> reserved=base(plan,trial);boolean conflict=false;
                            try{
                                for(Map.Entry<String,Object> entry:reserved.entrySet())if(observation.containsKey(entry.getKey())){
                                    Object declared=observation.get(entry.getKey());
                                    if(entry.getKey().equals("backend_build_identity"))declared=copyIdentity(declared);
                                    if(!Objects.equals(entry.getValue(),declared))conflict=true;
                                }
                                // Only analyzer-supported facts are read; unknown keys remain caller-owned.
                                for(String key:OBSERVATION_FIELDS)if(observation.containsKey(key))facts.put(key,observation.get(key));
                                // Backend output cannot replace scheduling or identity chosen before execution.
                                facts.putAll(reserved);
                                if(conflict){facts.put("execution_complete",false);markEnvironmentFailure(facts,"backend_reserved_field_mismatch");}
                            }catch(Exception | LinkageError e){facts.clear();facts.putAll(reserved);facts.put("status","invalid_observation");facts.put("execution_complete",false);facts.put("exclusion_reason",error("observation_error",e));}
                        }else {facts.put("status",measurementFailure==null?"observation_unavailable":"measurement_error");facts.put("execution_complete",false);if(measurementFailure!=null)facts.put("exclusion_reason",measurementFailure);}
                        try{if(!identityMatches(plan,variant,backend))markEnvironmentFailure(facts,"backend_identity_changed");}
                        catch(Exception | LinkageError e){markEnvironmentFailure(facts,error("backend_identity_error",e));}
                        try{if(!environment.after(trial))markEnvironmentFailure(facts,"environment_after_rejected");}
                        catch(InterruptedException e){Thread.currentThread().interrupt();markEnvironmentFailure(facts,error("environment_after_error",e));}
                        catch(Exception | LinkageError e){markEnvironmentFailure(facts,error("environment_after_error",e));}
                        // Journal first. If a caller concurrently mutates inputs, the downstream analyzer still
                        // rejects any incomplete or contradictory written row; stable observations are required.
                        appendPreservingInterrupt(journal,token,measured,facts);attempts++;
                        Map<String,Object> row=ProbeRecordBridge.record(measured,facts);
                        if(!acceptedForContinuing(row,plan.projections.get(caseName)))return new Result(false,attempts,"attempt_not_eligible");
                    }
                }
            }
            journal.releaseClaim(token);token=null;complete=true;return new Result(true,attempts,"capture_complete_not_accepted");
        } catch(IOException | RuntimeException | Error failure){pending=failure;throw failure;}
        finally {if(!complete&&token!=null)try{journal.closeClaimed(token);}catch(IOException | RuntimeException | Error close){if(pending!=null){if(close!=pending)pending.addSuppressed(close);}else throw close;}}
    }
}
