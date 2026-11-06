package io.github.jichuo1.dexmeguviz;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

/** Observations from an explicitly supplied APK snapshot; not runtime source authentication. */
public final class MethodSourceObservation {
    private MethodSourceObservation() {}
    private static final int REQUIRED_PROJECTION=1|2|4;
    private static final int RESULT_LIMIT=4;

    /** A copied result; its selected input scope is not a complete application or loader. */
    public static final class Result {
        public final String snapshotId,queryId;
        public final int executionStatus,coverage,decision,reason,visitedMethods,totalMethods;
        public final long unknownRows;
        public final boolean sourceScopeComplete,allInputMethodsScanned;
        public final NativeEngine.SourceSetInfo inputs;
        private final List<Observation> observations;
        private Result(NativeEngine.SourceSetInfo info,NativeEngine.QueryResult query,List<Observation> values,boolean allScanned) {
            snapshotId=info.snapshotId;queryId=query.queryId;executionStatus=query.executionStatus;coverage=query.coverage;
            decision=query.decision;reason=query.reason;visitedMethods=query.visitedMethods;totalMethods=query.totalMethods;
            unknownRows=query.unknownRows;sourceScopeComplete=info.sourceScopeComplete;allInputMethodsScanned=allScanned;
            inputs=info;observations=Collections.unmodifiableList(new ArrayList<>(values));
        }
        /** A zero count is not an absence or uniqueness decision. */
        public int observedCandidateCount(){return observations.size();}
        public Observation observedCandidate(int index){return observations.get(index);}
    }

    /** Copies static occurrence information; its loader origin always remains unverified. */
    public static final class Observation {
        public final String snapshotId,queryId;
        public final boolean inputScanIncomplete,sourceScopeComplete;
        public final NativeEngine.InputInfo input;
        public final NativeEngine.RawDexSourceInfo source;
        public final NativeEngine.MethodCandidate candidate;
        private final ApkMetadataPlan.LoaderDeclaration declaration;
        private Observation(String snapshotId,String queryId,boolean incomplete,boolean scope,NativeEngine.InputInfo input,
                NativeEngine.RawDexSourceInfo source,NativeEngine.MethodCandidate candidate,ApkMetadataPlan.LoaderDeclaration declaration) {
            this.snapshotId=snapshotId;this.queryId=queryId;inputScanIncomplete=incomplete;sourceScopeComplete=scope;
            this.input=input;this.source=source;this.candidate=candidate;this.declaration=declaration;
        }
        /** Explicit per-candidate reflection; loader code may run. Does not invoke the target or request its initialization. */
        public RuntimeMethodBinder.Result bind(ClassLoader loader,Object generation) {
            if(declaration==null)throw new IllegalStateException("plan has no loader declaration");
            if(generation==null||declaration.loader!=loader||declaration.generation!=generation)
                throw new IllegalArgumentException("loader or generation differs from plan declaration");
            return RuntimeMethodBinder.bind(loader,generation,candidate);
        }
    }

    private static boolean sha256(String value) {
        if(value==null||value.length()!=64)return false;
        for(int i=0;i<64;i++){char c=value.charAt(i);if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;}
        return true;
    }
    private static void check(boolean value,String message){if(!value)throw new IllegalStateException(message);}
    static boolean inputScanFinished(int status,int reason,long unknown,int visited,int total) {
        return status==0&&reason!=RESULT_LIMIT&&unknown==0&&visited==total;
    }

    /**
     * Executes a method-v1 query on this exact open APK snapshot and copies observations.
     * The request must project owner/name/prototype. Status, Unknown and early stopping are
     * preserved; candidate count alone never proves uniqueness, absence or loader scope.
     * Full input traversal does not imply that the query returned every match: intent and
     * query limits still govern its candidate list.
     */
    public static Result query(AndroidApkSources.Opened opened,byte[] queryJson) {
        if(opened==null||queryJson==null)throw new NullPointerException("opened source and query are required");
        byte[] request=queryJson.clone();
        synchronized(opened.snapshot) {
            NativeEngine.SourceSetInfo info=opened.snapshot.info();
            NativeEngine.QueryResult query=opened.snapshot.queryMethods(request);
            return assemble(opened.plan,info,query);
        }
    }
    private static Result assemble(ApkMetadataPlan plan,NativeEngine.SourceSetInfo info,NativeEngine.QueryResult query) {
            check(info.snapshotId!=null&&!info.snapshotId.isEmpty(),"missing snapshot identity");
            check(info.inputCount()==plan.entries().size(),"plan input count differs");
            int[] counts=new int[info.inputCount()];HashSet<String> occurrences=new HashSet<>();
            for(int i=0;i<counts.length;i++){
                NativeEngine.InputInfo input=info.input(i);ApkMetadataPlan.Entry entry=plan.entries().get(i);
                check(input!=null&&input.inputIndex==i&&input.format==NativeEngine.SOURCE_APK&&
                        entry.slot.equals(input.slot)&&entry.allowNoDex==input.allowNoDex&&sha256(input.sourceSha256),"plan/input mismatch");
            }
            for(int i=0;i<info.sourceCount();i++){
                NativeEngine.RawDexSourceInfo source=info.source(i);
                check(source!=null&&source.sourceIndex==i&&source.inputIndex>=0&&source.inputIndex<counts.length,"invalid source mapping");
                NativeEngine.InputInfo input=info.input(source.inputIndex);
                check(input.slot.equals(source.slot)&&source.occurrenceId!=null&&!source.occurrenceId.isEmpty()&&
                        occurrences.add(source.occurrenceId)&&sha256(source.sourceSha256)&&source.archiveEntryName!=null&&
                        source.archiveEntryIndex>=0,"invalid APK source identity");
                counts[source.inputIndex]++;
            }
            for(int i=0;i<counts.length;i++)check(info.input(i).sourceCount==counts[i],"input/source count mismatch");
            check(info.snapshotId.equals(query.snapshotId)&&query.queryId!=null&&query.queryId.startsWith("query:v1:"),"query/snapshot mismatch");
            check((query.projectionMask&REQUIRED_PROJECTION)==REQUIRED_PROJECTION,"owner/name/prototype projection required");
            check(query.visitedMethods>=0&&query.totalMethods>=query.visitedMethods&&query.unknownRows>=0,"invalid query counters");
            boolean allScanned=inputScanFinished(query.executionStatus,query.reason,query.unknownRows,query.visitedMethods,query.totalMethods);
            ArrayList<Observation> values=new ArrayList<>(query.candidateCount());
            for(int i=0;i<query.candidateCount();i++){
                NativeEngine.MethodCandidate candidate=query.candidate(i);
                check(candidate!=null&&candidate.sourceIndex>=0&&candidate.sourceIndex<info.sourceCount(),"candidate source missing");
                NativeEngine.RawDexSourceInfo source=info.source(candidate.sourceIndex);NativeEngine.InputInfo input=info.input(source.inputIndex);
                check(candidate.inputIndex==source.inputIndex&&source.slot.equals(candidate.sourceSlot)&&
                        source.occurrenceId.equals(candidate.occurrenceId)&&candidate.owner!=null&&candidate.name!=null&&
                        candidate.prototype!=null&&candidate.methodIndex>=0&&candidate.declarationOffset>=0,"candidate/source mismatch");
                values.add(new Observation(info.snapshotId,query.queryId,!allScanned,info.sourceScopeComplete,input,source,candidate,plan.loaderDeclaration));
            }
            return new Result(info,query,values,allScanned);
    }
}
