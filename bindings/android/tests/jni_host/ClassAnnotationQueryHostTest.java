package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class ClassAnnotationQueryHostTest {
    private static final String TYPE = "\"type\":\"Lfixture/Complex;\"";
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static byte[] json(String where,String suffix){
        return ("{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\"],\"where\":"+where+suffix+"}").getBytes(StandardCharsets.UTF_8);
    }
    private static byte[] query(String elementName,int value){
        return json("{\"annotation\":{"+TYPE+",\"visibility\":1,\"element\":{\"name\":\""+elementName+"\",\"int\":"+value+"}}}","");
    }
    private static void rejected(int expected,Runnable action){
        try{action.run();throw new AssertionError("expected native status "+expected);}
        catch(NativeEngine.NativeFailure e){check(e.status==expected,"status "+e.status+" expected "+expected);}
    }
    private static void nullRejected(Runnable action){
        try{action.run();throw new AssertionError("null accepted");}catch(NullPointerException expected){}
    }
    private static void outcome(NativeEngine.EntityResult value,int count,long unknown){
        check(value.executionStatus==0 && value.relation==1,"successful class result");
        check(value.queryId.startsWith("query:v24:") && value.snapshotId!=null,"v24 query and snapshot identities");
        check(value.coverage==1 && value.candidateCount()==count && value.unknownRows==unknown,"partial scope, candidates and unknown");
        if(unknown>0)check(value.reason==6,"unknown reason");
    }
    private static void matchingRow(NativeEngine.EntityCandidate row,int source,String slot){
        check(row.relation==1 && row.sourceIndex==source && row.inputIndex==source,"source identity");
        check(row.localIndex==0 && row.referenceIndex==2 && "Lfixture/Annotated;".equals(row.typeDescriptor),"class identity");
        check(slot.equals(row.sourceSlot) && row.occurrenceId!=null,"source slot and occurrence");
    }
    public static void main(String[] args)throws Exception{
        check(args.length==1,"fixture argument");byte[] dex=Files.readAllBytes(Path.of(args[0]));
        byte[] match=query("n",-7),wrong=query("n",7),missing=query("absent",0);
        byte[] notMissing=json("{\"not\":{\"annotation\":{"+TYPE+",\"visibility\":1,\"element\":{\"name\":\"absent\",\"int\":0}}}}","");
        byte[] scope=json("{\"annotation\":{"+TYPE+"}}",",\"scope\":{\"slots\":[\"one\"]}");
        byte[] old="{\"schema_version\":1,\"relation\":\"class_defs\"}".getBytes(StandardCharsets.UTF_8);
        NativeEngine.EntityResult retained;
        try(NativeEngine.Snapshot single=NativeEngine.openRawDex(dex,"single")){
            NativeEngine.EntityResult result=ClassAnnotationQuery.execute(single,match);outcome(result,1,0);
            matchingRow(result.candidate(0),0,"single");
            outcome(ClassAnnotationQuery.execute(single,wrong),0,0);
            NativeEngine.EntityResult unknown=ClassAnnotationQuery.execute(single,missing);outcome(unknown,0,1);
            NativeEngine.EntityResult negated=ClassAnnotationQuery.execute(single,notMissing);outcome(negated,3,1);
            for(int i=0;i<negated.candidateCount();++i)check(negated.candidate(i).localIndex!=0,"negation must not turn Unknown into a match");
            byte[] exists=json("{\"annotation\":{"+TYPE+",\"element\":{\"name\":\"absent\",\"int\":0}}}",",\"intent\":\"exists\"");
            check(ClassAnnotationQuery.execute(single,exists).decision==1,"Unknown exists is undetermined");
            rejected(3,()->single.queryEntities(match));rejected(3,()->single.queryMethods(match));
            rejected(3,()->ClassAnnotationQuery.execute(single,old));rejected(3,()->ClassAnnotationQuery.execute(single,scope));
            byte[] tooMany=json("{\"annotation\":{"+TYPE+"}}",",\"max_results\":4097");
            byte[] tooMuchWork=json("{\"annotation\":{"+TYPE+"}}",",\"max_work\":100000001");
            rejected(4,()->ClassAnnotationQuery.execute(single,tooMany));rejected(4,()->ClassAnnotationQuery.execute(single,tooMuchWork));
            byte[] identityOnly=json("{\"annotation\":{"+TYPE+"}}",",\"projection\":[\"identity\"]");
            NativeEngine.EntityResult projected=ClassAnnotationQuery.execute(single,identityOnly);outcome(projected,1,0);
            check(projected.candidate(0).typeDescriptor==null,"omitted projection must remain null");
            nullRejected(()->ClassAnnotationQuery.execute(single,null));
        }
        nullRejected(()->ClassAnnotationQuery.execute((NativeEngine.Snapshot)null,match));
        nullRejected(()->ClassAnnotationQuery.execute((NativeEngine.SourceSetSnapshot)null,match));
        NativeEngine.SourceSetSnapshot set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"});
        try{
            retained=ClassAnnotationQuery.execute(set,match);outcome(retained,2,0);
            matchingRow(retained.candidate(0),0,"one");matchingRow(retained.candidate(1),1,"two");
            check(!retained.candidate(0).occurrenceId.equals(retained.candidate(1).occurrenceId),"equal bytes remain distinct occurrences");
            outcome(ClassAnnotationQuery.execute(set,wrong),0,0);outcome(ClassAnnotationQuery.execute(set,missing),0,2);
            NativeEngine.EntityResult negated=ClassAnnotationQuery.execute(set,notMissing);outcome(negated,6,2);
            for(int i=0;i<negated.candidateCount();++i)check(negated.candidate(i).localIndex!=0,"two-source Unknown negation");
            rejected(3,()->set.queryEntities(match));rejected(3,()->ClassAnnotationQuery.execute(set,old));rejected(3,()->ClassAnnotationQuery.execute(set,scope));
        }finally{set.close();}
        check("Lfixture/Annotated;".equals(retained.candidate(0).typeDescriptor)&&"two".equals(retained.candidate(1).sourceSlot),"copied result survives snapshot close");
        rejected(7,()->ClassAnnotationQuery.execute(set,match));
        System.out.println("PASS v24 class annotation JNI, Unknown, occurrence, scope rejection and lifetime");
    }
}
