package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class JniReflectionMethodUsesTest {
    static void check(boolean x,String why){if(!x)throw new AssertionError(why);}
    static byte[] b(String x){return x.getBytes(StandardCharsets.UTF_8);}
    static final String QUERY="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"all\":[{\"name\":\"uses\"},{\"flags\":{\"domain\":\"reflection\",\"value\":8}},{\"using_strings\":{\"all\":[\"used-string\"]}}]},\"intent\":\"unique\",\"max_results\":100,\"required_capabilities\":[\"reflection_flags_static\",\"reflection_method_uses\"]}";
    static void rejected(int expected,Runnable r){try{r.run();throw new AssertionError("accepted");}catch(NativeEngine.NativeFailure e){check(e.status==expected,"status "+e.status);}}
    static void job(NativeEngine.EntityJob job,NativeEngine.EntityResult result){
        try(job){int count=0;boolean ended=false;for(int i=0;i<100;i++){var poll=job.next(10000);if(poll.kind==2){ended=true;break;}check(poll.kind==0&&poll.batch!=null,"batch");check(poll.batch.coverage==1&&poll.batch.decision==0,"provisional");count+=poll.batch.candidateCount();}check(ended,"missing EOS");
            var s=job.waitFor(10000);check(s.terminal&&s.executionStatus==0&&s.coverage==result.coverage&&s.decision==result.decision&&s.reason==result.reason&&s.candidateCount==count&&count==result.candidateCount()&&s.unknownRows==result.unknownRows&&s.queryId.equals(result.queryId)&&s.snapshotId.equals(result.snapshotId),"terminal");}
    }
    static void result(String label,NativeEngine.EntityResult r,int rows,int unknown){
        check(r.executionStatus==0&&r.coverage==1&&r.candidateCount()==rows&&r.unknownRows==unknown&&r.queryId.startsWith("query:v15:"),label);
        for(int i=0;i<rows;i++){var c=r.candidate(i);check(c.relation==0&&"uses".equals(c.name)&&c.sourceIndex==i&&c.inputIndex==i&&c.sourceSlot!=null&&c.occurrenceId!=null,"origin");}
        System.out.println("CASE\t"+label+"\t"+r.queryId+"\t"+r.coverage+"\t"+r.decision+"\t"+r.reason+"\t"+rows+"\t"+unknown);
    }
    public static void main(String[] args)throws Exception{
        byte[] dex=Files.readAllBytes(Path.of(args[0])),unknown=Files.readAllBytes(Path.of(args[1])),q=b(QUERY);
        try(var single=NativeEngine.openRawDex(dex,"a")){
            var r=single.queryReflectionMethodUses(q);result("single",r,1,0);job(single.startReflectionMethodUsesJob(q,1,1,0),r);
            rejected(3,()->single.queryMethods(q));rejected(3,()->single.queryEntities(q));rejected(3,()->single.startEntityJob(q,1,1,0));
            rejected(3,()->single.queryReflectionMethodUses(b("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":true}")));
            rejected(3,()->single.queryReflectionMethodUses(b(QUERY.replace("\"intent\":\"unique\"","\"scope\":{\"slots\":[\"a\"]},\"intent\":\"unique\""))));
            rejected(4,()->single.queryReflectionMethodUses(b(QUERY.replace("\"max_results\":100","\"max_results\":4097"))));
        }
        try(var multi=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"a","b"})){
            var r=multi.queryReflectionMethodUses(q);result("multi",r,2,0);job(multi.startReflectionMethodUsesJob(q,1,1,0),r);
        }
        try(var single=NativeEngine.openRawDex(unknown,"a")){
            var r=single.queryReflectionMethodUses(q);result("unknown-single",r,0,1);job(single.startReflectionMethodUsesJob(q,1,1,0),r);
        }
        try(var multi=NativeEngine.openRawDexSet(new byte[][]{unknown,unknown},new String[]{"a","b"})){
            var r=multi.queryReflectionMethodUses(q);result("unknown-multi",r,0,2);job(multi.startReflectionMethodUsesJob(q,1,1,0),r);
        }
        System.out.println("PASS JNI v15 sync and provisional jobs, source identities, Unknown and old-entry rejection");
    }
}
