package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Fixed v14 static metadata graph checks; no ART equivalence claim. */
public final class JniReflectionGraphTest {
    static void check(boolean condition,String detail){if(!condition)throw new AssertionError(detail);}
    static byte[] json(String s){return s.getBytes(StandardCharsets.UTF_8);}
    static String flag(String field,String mode,int bits){return "{\""+field+"\":{\"domain\":\"reflection\",\"mode\":\""+mode+"\",\"value\":"+bits+"}}";}
    static String scan(String relation,String where){return "{\"op\":\"scan\",\"relation\":\""+relation+"\""+(where==null?"":",\"where\":"+where)+"}";}
    static String query(String relation){return "{\"schema_version\":1,\"relation\":"+relation+",\"intent\":\"enumerate\",\"required_capabilities\":[\"reflection_flags_static\",\"reflection_relational\"]}";}
    static void reject(int status,Runnable call){try{call.run();throw new AssertionError("unsupported accepted");}catch(NativeEngine.NativeFailure e){check(e.status==status,"status="+e.status);}}
    static GraphResult verify(NativeEngine.SourceSetSnapshot snap,String relation){
        byte[] q=json(query(relation));GraphResult expected=snap.queryGraph(q);
        check(expected.queryId.startsWith("query:v14:")&&expected.coverage==1,"profile/scope");
        try(var job=snap.startGraphJob(q,1,1,0)){
            var rows=JniGraphJobTest.drain(job,expected);var terminal=job.waitFor(10000);
            check(terminal.terminal&&terminal.executionStatus==expected.executionStatus&&terminal.coverage==expected.coverage&&terminal.unknownRows==expected.unknownRows,"terminal");
            check(terminal.queryId.equals(expected.queryId)&&terminal.snapshotId.equals(expected.snapshotId)&&terminal.candidateCount==rows.size(),"identity");
            check(rows.size()==expected.rowCount(),"row count");
            for(int i=0;i<rows.size();i++)JniGraphJobTest.row(rows.get(i),expected.row(i));
        }
        return expected;
    }
    public static void main(String[] args)throws Exception{
        byte[] dex=Files.readAllBytes(Path.of(args[0]));
        try(var snap=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})){
            String reflected=flag("flags","contains",1);
            String fieldRefs=scan("field_refs",reflected);
            GraphResult scan=verify(snap,fieldRefs);
            check(scan.rowCount()==6&&scan.unknownRows==2&&scan.reason==6,"known and Unknown refs");
            check(scan.row(0).entity.accessFlags!=null&&scan.row(0).entity.accessFlags==1L,"raw flags preserved");
            check(!scan.source(0).occurrenceId.equals(scan.source(1).occurrenceId),"occurrence");
            String filtered="{\"op\":\"filter\",\"input\":"+scan("field_refs",null)+",\"where\":"+reflected+"}";
            check(verify(snap,filtered).rowCount()==6,"filter");
            String left=scan("field_defs",flag("flags","exact",9));String right=scan("field_refs",null);
            String join="{\"op\":\"join\",\"on\":\"local_definition\",\"left\":"+left+",\"right\":"+right+"}";
            var joined=verify(snap,join);check(joined.rowCount()==2&&joined.row(0).bindingCount()==2&&joined.row(0).linkCount()==1,"join");
            String semi=join.replace("\"join\"","\"semi_join\"");
            var proof=verify(snap,semi);check(proof.rowCount()==2&&proof.row(0).proofBindingCount()>0,"semi proof");
            String bag="{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":["+left+","+left+"]}";
            check(verify(snap,bag).rowCount()==4,"bag");
            check(verify(snap,"{\"op\":\"distinct\",\"identity\":\"entity\",\"input\":"+bag+"}").rowCount()==2,"distinct");
            String group="{\"op\":\"group_by_owner\",\"inputs\":[{\"op\":\"label\",\"label\":\"F\",\"input\":"+left+"}],\"required_roles\":[\"F\"]}";
            verify(snap,group);
            String unsupported="{\"schema_version\":1,\"relation\":\"field_refs\",\"where\":"+reflected+",\"required_capabilities\":[\"reflection_flags_static\"]}";
            reject(3,()->snap.queryGraph(json(unsupported)));reject(3,()->snap.startGraphJob(json(unsupported),1,1,0));
            String scoped="{\"op\":\"scan\",\"relation\":\"field_refs\",\"where\":"+reflected+",\"scope\":{\"slots\":[\"one\"]}}";
            reject(3,()->snap.queryGraph(json(query(scoped))));reject(3,()->snap.startGraphJob(json(query(scoped)),1,1,0));
            reject(3,()->snap.queryEntities(json(query(fieldRefs))));
        }
        try(var single=NativeEngine.openRawDex(dex,"one")){
            byte[] q=json(query(scan("method_defs",flag("flags","contains",1))));
            var expected=single.queryGraph(q);check(expected.queryId.startsWith("query:v14:"),"single profile");
            try(var job=single.startGraphJob(q,1,1,0)){
                var rows=JniGraphJobTest.drain(job,expected);var terminal=job.waitFor(10000);
                check(terminal.terminal&&terminal.executionStatus==expected.executionStatus&&rows.size()==expected.rowCount(),"single job");
            }
        }
        System.out.println("PASS v14 reflection graph sync and Job static metadata");
    }
}
