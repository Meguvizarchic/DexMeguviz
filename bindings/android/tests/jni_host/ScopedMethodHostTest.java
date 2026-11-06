package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Fixed host JVM/JNI sample; scoped coverage is not app or loader authentication. */
public final class ScopedMethodHostTest {
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static byte[] query(String slots,String intent,String name){return ("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\""+name+"\"},\"intent\":\""+intent+"\",\"max_results\":100,\"scope\":{\"slots\":"+slots+"}}").getBytes(StandardCharsets.UTF_8);}
    private static void rejected(int status,Runnable body){try{body.run();throw new AssertionError("expected native failure");}catch(NativeEngine.NativeFailure failure){check(failure.status==status,"unexpected failure "+failure.status);}}
    public static void main(String[] args)throws Exception{
        check(args.length==3,"fixtures");byte[] base=Files.readAllBytes(Path.of(args[0])),resource=Files.readAllBytes(Path.of(args[1])),code=Files.readAllBytes(Path.of(args[2]));
        NativeEngine.SourceSetSnapshot set=NativeEngine.openSources(new byte[][]{base,resource,code},new String[]{"base","resource","code"},new int[]{NativeEngine.SOURCE_APK,NativeEngine.SOURCE_APK,NativeEngine.SOURCE_RAW_DEX},new boolean[]{false,true,false});
        byte[] scoped=query("[\"code\"]","unique","uses");
        rejected(3,()->set.queryMethods(scoped));rejected(3,()->set.startMethodJob(scoped,1,1,0));
        var result=ScopedMethodQuery.execute(set,scoped);check(result.query.executionStatus==0&&result.query.coverage==0&&result.query.decision==3&&result.query.candidateCount()==1,"unique selected scope");
        check(result.scope.inputSlotCount()==1&&result.scope.inputSlot(0).equals("code")&&result.scope.sourceCount()==1&&result.scope.sourceIndex(0)==3&&!result.scope.snapshotScopeComplete&&!result.scope.sourceScopeAuthenticated,"declared scope metadata");
        var candidate=result.query.candidate(0);check(candidate.sourceIndex==3&&candidate.inputIndex==2&&candidate.sourceSlot.equals("code"),"origin indices");
        var missing=ScopedMethodQuery.execute(set,query("[\"code\"]","exists","not-present"));check(missing.query.coverage==0&&missing.query.decision==2&&missing.query.candidateCount()==0,"absence within declared code scope");
        var emptyResource=ScopedMethodQuery.execute(set,query("[\"resource\"]","exists","uses"));check(emptyResource.query.coverage==0&&emptyResource.query.decision==2&&emptyResource.scope.inputSlotCount()==1&&emptyResource.scope.sourceCount()==0,"empty resource scope");
        var empty=ScopedMethodQuery.execute(set,query("[]","exists","uses"));check(empty.query.coverage==0&&empty.query.decision==2&&empty.scope.inputSlotCount()==0&&empty.scope.sourceCount()==0,"explicit empty scope");
        rejected(8,()->ScopedMethodQuery.execute(set,query("[\"missing\"]","exists","uses")));rejected(8,()->ScopedMethodQuery.start(set,query("[\"missing\"]","exists","uses"),1,1,0));
        rejected(3,()->ScopedMethodQuery.execute(set,"{\"schema_version\":1,\"relation\":\"method_defs\"}".getBytes(StandardCharsets.UTF_8)));
        ScopedMethodQuery.Job job=ScopedMethodQuery.start(set,scoped,1,1,0);check(job.scope.inputSlot(0).equals("code")&&job.scope.sourceCount()==1&&job.scope.sourceIndex(0)==3,"job declared scope");set.close();
        int delivered=0;for(int i=0;i<20;i++){var poll=job.next(1000);if(poll.kind==1)continue;if(poll.kind==2)break;check(poll.kind==0&&poll.batch.coverage==1&&poll.batch.decision==0,"batch provisional");delivered+=poll.batch.candidateCount();}
        var status=job.waitFor(1000);check(delivered==1&&status.terminal&&status.executionStatus==0&&status.coverage==0&&status.decision==3,"job terminal selected scope");job.close();
        rejected(7,()->ScopedMethodQuery.execute(set,scoped));
        try(NativeEngine.Snapshot single=NativeEngine.openRawDex(code,"solo")){var one=ScopedMethodQuery.execute(single,query("[\"solo\"]","unique","uses"));check(one.query.coverage==0&&one.query.decision==3&&one.scope.sourceIndex(0)==0&&!one.scope.snapshotScopeComplete,"single scoped source");}
        System.out.println("PASS scoped method JNI sync/Job: selected input slots, multidex/resource mapping, empty/absence, legacy rejection and source-close lifetime");
    }
}
