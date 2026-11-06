package io.github.jichuo1.dexmeguviz.precompute;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.BooleanSupplier;
import static io.github.jichuo1.dexmeguviz.precompute.OfflineJson.*;

/** Opt-in offline static candidates. No native loading, reflection, CLI or
 * package-supplied code is executed. Caller independently trusts the receipt. */
public final class PrecomputedCandidates {
    public static final String LOCAL_VERIFIER="dex-local-bytes-v1";
    public static final String IMPLEMENTATION="jvm-precompute-consumer-v1";
    public static final String OPCODE_TABLE_SHA256="7eaa06d9d7566adf82e23dea293aa9c0b41f7838fb698a1a8c19f756f78222c7";
    private static final Set<String> PROFILES=Collections.unmodifiableSet(new HashSet<>(Arrays.asList("dex-query-method-v1","dex-query-entity-v2","dex-query-relational-v3","dex-query-use-v4","dex-query-expand-v5","dex-query-use-target-symbol-v16","dex-query-type-uses-v21","dex-query-method-type-uses-v22")));
    private PrecomputedCandidates(){}
    public static final class Failure extends RuntimeException {
        public final String status;
        Failure(String status,String message){super(message);this.status=status;}
    }
    public static final class Limits {
        public final long maxMaterializedDexBytes,maxLocalWork,deadlineAfterMs;public final BooleanSupplier cancelled;
        public Limits(){this(128L<<20,100000000L,30000L,null);}
        public Limits(long maxMaterializedDexBytes,long maxLocalWork,long deadlineAfterMs,BooleanSupplier cancelled){if(maxMaterializedDexBytes<1||maxMaterializedDexBytes>(512L<<20)||maxLocalWork<1||maxLocalWork>1000000000L||deadlineAfterMs<0||deadlineAfterMs>3600000L)throw new IllegalArgumentException("invalid offline limits");this.maxMaterializedDexBytes=maxMaterializedDexBytes;this.maxLocalWork=maxLocalWork;this.deadlineAfterMs=deadlineAfterMs;this.cancelled=cancelled;}
    }
    public static final class SourceInput {
        public final File file;public final String slot,role,format;
        /** slot/role are caller-selected logical identities, independent of the
         * current physical file path; null format auto-detects raw DEX/APK. */
        public SourceInput(File file,String slot,String role,String format){if(file==null||slot==null||role==null)throw new NullPointerException("current source fields");this.file=new File(file.getPath());this.slot=slot;this.role=role;this.format=format;}
        public SourceInput(File file,String slot,String role){this(file,slot,role,null);}
    }
    public static final class Source {
        public final int sourceIndex,inputIndex;public final String slot,role,inputSha256,dexSha256,dexEntry,contentId,logicalDexId,occurrenceId;public final Long centralIndex;public final long inputBytes,dexBytes;
        Source(Map<String,Object> source,Map<String,Object> input){sourceIndex=(int)num(source.get("source_index"));inputIndex=(int)num(source.get("input_index"));slot=str(input.get("slot"));role=str(input.get("role"));inputSha256=str(input.get("sha256"));dexSha256=str(source.get("sha256"));dexEntry=(String)source.get("entry");centralIndex=source.get("central_index")==null?null:Long.valueOf(num(source.get("central_index")));inputBytes=num(input.get("bytes"));dexBytes=num(source.get("bytes"));contentId="sha256:raw-dex:v1:"+dexBytes+":"+dexSha256;logicalDexId="logical-dex:v1:"+frame(contentId)+"header-offset:0";occurrenceId="occurrence:v2:"+hash(utf8("dmg:occurrence:v2:"+frame("cli-v1")+frame(dexEntry==null?"raw-input":"archive-entry")+frame(slot)+frame(role)+frame(dexEntry==null?"":dexEntry)+frame(contentId)));}
    }
    public static final class Candidate {
        public final int sourceIndex;public final Source source;
        /** Verified local identity/descriptor or event, separately from producer
         * claims and unverified query completeness. No native pointers. */
        public final Map<String,Object> verifiedPrimary,raw;
        public final String relation,owner,name,prototype,typeDescriptor,stringValue,targetDomain;
        public final Long localIndex,referenceIndex,callerOrdinal,callerMethodRef,dexPc,targetIndex,accessFlags,declarationOffset,codeOffset;
        public final Boolean hasLocalDefinition;
        private static Long optionalNumber(Map<String,Object> map,String key){return map.get(key)==null?null:Long.valueOf(num(map.get(key)));}
        Candidate(Map<String,Object> raw,Map<String,Object> certificate,SourceCatalog catalog){sourceIndex=(int)num(certificate.get("source_index"));source=catalog.sources.get(sourceIndex);boolean entity=certificate.containsKey("value");Object value=entity?certificate.get("value"):certificate.get("event");verifiedPrimary=obj(freeze(value));this.raw=obj(freeze(raw));
            relation=entity?str(verifiedPrimary.get("relation")):str(raw.get("relation"));localIndex=entity?optionalNumber(verifiedPrimary,"local_index"):null;referenceIndex=entity?optionalNumber(verifiedPrimary,"reference_index"):null;
            callerOrdinal=entity?null:optionalNumber(verifiedPrimary,"method_ordinal");Map<String,Object> fields=entity?verifiedPrimary:catalog.dex(sourceIndex).describe("method_defs",callerOrdinal.longValue());callerMethodRef=entity?null:optionalNumber(fields,"reference_index");
            owner=(String)fields.get("owner");name=(String)fields.get("name");prototype=(String)fields.get("prototype");typeDescriptor=(String)fields.get("type_descriptor");stringValue=(String)fields.get("value");accessFlags=optionalNumber(fields,"access_flags");declarationOffset=optionalNumber(fields,"declaration_offset");codeOffset=optionalNumber(fields,"code_offset");hasLocalDefinition=entity?(Boolean)fields.get("has_local_definition"):null;
            dexPc=entity?null:optionalNumber(verifiedPrimary,"dex_pc");targetIndex=entity?null:optionalNumber(verifiedPrimary,"target_index");targetDomain=entity?null:(String)verifiedPrimary.get("target_domain");}
    }
    public static final class Rule {
        public final String id,profile,queryId;public final Object version;
        public final boolean queryDecisionVerified=false,completeEnumerationVerified=false;
        public final String origin="UNVERIFIED",runtimeBinding="NotPerformed";
        public final Map<String,Object> query,roles,producerClaim;
        public final List<Candidate> candidates;public final List<Object> frontiers,certificates;
        private static Object claimScalar(Object value){return value instanceof String||value instanceof BigInteger||value instanceof Boolean?value:null;}
        Rule(Map<String,Object> item,Map<String,Map<String,Object>> certified,SourceCatalog catalog){id=str(item.get("id"));profile=str(item.get("profile"));queryId=str(item.get("query_id"));version=freeze(item.get("version"));query=obj(freeze(item.get("query")));roles=obj(freeze(item.get("roles")));Map<String,Object> result=obj(item.get("result"));List<Object> rows=arr(result.get("candidates"));List<Candidate> values=new ArrayList<>();for(int i=0;i<rows.size();++i)values.add(new Candidate(obj(rows.get(i)),certified.get("/candidates/"+i),catalog));candidates=Collections.unmodifiableList(values);frontiers=arr(freeze(result.containsKey("frontiers")?result.get("frontiers"):new ArrayList<Object>()));certificates=arr(freeze(item.get("certificates")));Map<String,Object> qp=result.get("query_profile") instanceof Map?obj(result.get("query_profile")):Collections.emptyMap();Map<String,Object> v1=result.get("profile_v1") instanceof Map?obj(result.get("profile_v1")):Collections.emptyMap();Map<String,Object> runtime=v1.get("runtime") instanceof Map?obj(v1.get("runtime")):Collections.emptyMap();Map<String,Object> plan=v1.get("plan") instanceof Map?obj(v1.get("plan")):Collections.emptyMap();Map<String,Object> scope=result.get("query_scope") instanceof Map?obj(result.get("query_scope")):Collections.emptyMap();Object indices=scope.get("sources");if(!(indices instanceof List)||((List<?>)indices).size()!=catalog.sources.size())indices=null;else for(Object index:(List<?>)indices)if(!(index instanceof BigInteger)||((BigInteger)index).signum()<0){indices=null;break;}producerClaim=obj(freeze(map("execution_status",claimScalar(result.get("execution_status")),"coverage",claimScalar(result.get("coverage")),"decision",claimScalar(result.get("decision")),"reason",claimScalar(result.get("reason")),"visited_methods",claimScalar(result.get("visited_methods")),"total_methods",claimScalar(result.get("total_methods")),"scope_complete",claimScalar(result.get("scope_complete")),"unknown_rows",claimScalar(result.get("unknown_rows")),"unknown_rows_present",result.containsKey("unknown_rows"),"query_profile_unknown_rows",claimScalar(qp.get("unknown_rows")),"query_scope_complete",claimScalar(scope.get("complete")),"query_scope_explicit",claimScalar(scope.get("explicit")),"query_scope_sources",indices,"profile_v1_present",result.containsKey("profile_v1"),"profile_v1_producer",claimScalar(v1.get("producer")),"profile_v1_phase",claimScalar(v1.get("phase")),"profile_v1_query_id",claimScalar(plan.get("query_id")),"profile_v1_unknown_rows",claimScalar(runtime.get("unknown_rows")),"profile_v1_scope_complete",claimScalar(runtime.get("scope_complete")))));}
    }
    public static final class Result {
        public final String status="CandidatesLocallyVerified",origin="UNVERIFIED",runtimeBinding="NotPerformed";
        public final boolean queryDecisionVerified=false,completeEnumerationVerified=false,packageAuthenticated=false;
        public final String modelVersion,snapshotId,localVerifier=LOCAL_VERIFIER,implementation=IMPLEMENTATION;
        public final Map<String,Object> sourceIdentity;public final List<Source> sources;public final List<Rule> rules;
        public final long localWork,materializedDexBytes;
        Result(String model,Map<String,Object> identity,List<Source> sources,List<Rule> rules,Budget b,String snapshotId){this.snapshotId=snapshotId;modelVersion=model;sourceIdentity=obj(freeze(identity));this.sources=Collections.unmodifiableList(new ArrayList<>(sources));this.rules=Collections.unmodifiableList(new ArrayList<>(rules));localWork=b.work;materializedDexBytes=b.materialized;}
        public Rule rule(String id){for(Rule rule:rules)if(rule.id.equals(id))return rule;throw new IllegalArgumentException("offline rule not present");}
    }
    static byte[] utf8(String value){try{java.nio.ByteBuffer buffer=java.nio.charset.StandardCharsets.UTF_8.newEncoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(value));byte[] out=new byte[buffer.remaining()];buffer.get(out);return out;}catch(java.nio.charset.CharacterCodingException e){throw new Failure("SourceMismatch","source identity is not UTF-8");}}
    static String frame(String value){return utf8(value).length+":"+value;}
    static MessageDigest sha(){try{return MessageDigest.getInstance("SHA-256");}catch(NoSuchAlgorithmException e){throw new IllegalStateException("SHA-256 unavailable",e);}}
    static String hex(byte[] bytes){char[] result=new char[bytes.length*2],digits="0123456789abcdef".toCharArray();for(int i=0;i<bytes.length;++i){int b=bytes[i]&255;result[2*i]=digits[b>>>4];result[2*i+1]=digits[b&15];}return new String(result);}
    static String hash(byte[] bytes){return hex(sha().digest(bytes));}
    static String hash(byte[] bytes,int offset,int length){MessageDigest d=sha();d.update(bytes,offset,length);return hex(d.digest());}
    private static long le(byte[] bytes,int at,int width){need(at>=0&&at<=bytes.length-width,"InvalidPackage","header range");long value=0;for(int i=0;i<width;i++)value|=(long)(bytes[at+i]&255)<<(8*i);return value;}
    private static void hashText(Object value){need(value instanceof String&&((String)value).matches("[0-9a-f]{64}"),"InvalidPackage","digest format");}
    public static Result consume(byte[] packageBytes,byte[] independentlyTrustedExpected,String currentModelVersion,boolean currentScopeComplete,List<SourceInput> currentSources){return consume(packageBytes,independentlyTrustedExpected,currentModelVersion,currentScopeComplete,currentSources,new Limits());}
    public static Result consume(byte[] packageBytes,byte[] independentlyTrustedExpected,String currentModelVersion,boolean currentScopeComplete,List<SourceInput> currentSources,Limits limits){
        if(packageBytes==null||independentlyTrustedExpected==null||currentModelVersion==null||currentSources==null||limits==null)throw new NullPointerException("offline input");
        need(packageBytes.length<=16*1024*1024+56&&independentlyTrustedExpected.length<=16*1024*1024,"BudgetExceeded","offline package bytes");Budget b=new Budget(limits);byte[] binary=packageBytes.clone(),expectation=independentlyTrustedExpected.clone();Map<String,Object> expected=obj(parse(expectation,b));equal(expected.get("schema_version"),n(1),"Unsupported","expectation version");hashText(expected.get("package_sha256"));equal(hash(binary),expected.get("package_sha256"),"DigestMismatch","independent package hash");
        need(binary.length>=56,"InvalidPackage","truncated package header");byte[] magic={'D','M','G','P','R','E','0','1'};for(int i=0;i<8;i++)need(binary[i]==magic[i],"Unsupported","package magic");need(le(binary,8,4)==1&&le(binary,12,4)==56,"Unsupported","package version/header");long length=le(binary,16,8);need(length>=0&&length==binary.length-56,"InvalidPackage","payload extent");equal(hash(binary,56,(int)length),hex(Arrays.copyOfRange(binary,24,56)),"DigestMismatch","payload checksum");
        Map<String,Object> payload=obj(parse(Arrays.copyOfRange(binary,56,binary.length),b));need(payload.keySet().equals(new HashSet<>(Arrays.asList("format_version","model_version","source_identity","engine_sha256","local_verifier","opcode_table_sha256","rules"))),"InvalidPackage","payload fields");equal(payload.get("format_version"),n(1),"Unsupported","payload version");equal(payload.get("local_verifier"),LOCAL_VERIFIER,"Unsupported","local verifier");equal(payload.get("opcode_table_sha256"),OPCODE_TABLE_SHA256,"VersionMismatch","fixed local opcode table");hashText(payload.get("engine_sha256"));
        for(String field:Arrays.asList("model_version","engine_sha256","local_verifier","opcode_table_sha256","source_identity"))equal(payload.get(field),expected.get(field),"VersionMismatch","independent expectation "+field);equal(currentModelVersion,expected.get("model_version"),"VersionMismatch","current model");
        need(currentSources.size()>=1&&currentSources.size()<=64,"BudgetExceeded","source input count");
        List<SourceInput> inputs=new ArrayList<>(currentSources);SourceCatalog catalog=SourceCatalog.open(inputs,currentScopeComplete,b);equal(catalog.identity,expected.get("source_identity"),"SourceMismatch","current ordered source identity");
        List<Object> records=arr(payload.get("rules")),wanted=arr(expected.get("rules"));need(records.size()>=1&&records.size()<=128&&records.size()==wanted.size(),"VersionMismatch","rule count");List<Rule> result=new ArrayList<>();Set<String> ids=new HashSet<>();
        for(int i=0;i<records.size();++i){b.charge(1);Map<String,Object> r=obj(records.get(i)),e=obj(wanted.get(i));need(PROFILES.contains(str(r.get("profile"))),"Unsupported","local profile");equal(r.get("local_verifier"),LOCAL_VERIFIER,"Unsupported","rule verifier");need(ids.add(str(r.get("id"))),"InvalidPackage","duplicate rule");Map<String,Object> key=new LinkedHashMap<>(r);for(String field:Arrays.asList("result","certificates","query","roles"))key.remove(field);key.put("roles_sha256",hash(canonical(r.get("roles"),b)));equal(key,e,"VersionMismatch","rule/query/role expectation");equal(hash(canonical(r.get("query"),b)),e.get("query_sha256"),"VersionMismatch","query bytes");Map<String,Object> output=obj(r.get("result"));equal(output.get("query_id"),e.get("query_id"),"VersionMismatch","query identity");equal(output.get("profile"),e.get("profile"),"VersionMismatch","result profile");equal(output.get("snapshot_id"),catalog.snapshotId,"SourceMismatch","result snapshot identity");
            List<Object> rows=arr(output.get("candidates"));need(rows.size()<=4096,"BudgetExceeded","candidate count");for(Map.Entry<String,Object> role:obj(r.get("roles")).entrySet()){need(role.getKey().length()>=1&&role.getKey().codePointCount(0,role.getKey().length())<=128,"InvalidPackage","role name");for(Object index:arr(role.getValue()))need(num(index)>=0&&num(index)<rows.size(),"InvalidPackage","role candidate index");}
            Map<String,Map<String,Object>> checked=new LocalCertificates(catalog,b).verify(output,arr(r.get("certificates")));result.add(new Rule(r,checked,catalog));
        }
        catalog.recheckInputs();b.check();return new Result(currentModelVersion,catalog.identity,catalog.sources,result,b,catalog.snapshotId);
    }
}
