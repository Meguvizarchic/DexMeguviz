package io.github.jichuo1.dexmeguviz;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

public final class JniEntityTest {
    private static void check(boolean value,String what){if(!value)throw new AssertionError(what);}
    private static byte[] query(String relation,String where){return ("{\"schema_version\":1,\"relation\":\""+relation+"\",\"where\":"+where+",\"intent\":\"enumerate\"}").getBytes(StandardCharsets.UTF_8);}
    private static byte[] json(String value){return value.getBytes(StandardCharsets.UTF_8);}
    private static void status(int expected,Runnable call){try{call.run();throw new AssertionError("expected native failure");}catch(NativeEngine.NativeFailure e){check(e.status==expected,"status "+e.status);}}
    public static void main(String[] args)throws Exception{
        check(args.length==5,"fixture arguments");
        byte[] dex=Files.readAllBytes(Path.of(args[0])), apk=Files.readAllBytes(Path.of(args[1]));
        byte[] resource=Files.readAllBytes(Path.of(args[2])), unicode=Files.readAllBytes(Path.of(args[3]));
        byte[] emptyAndNul=Files.readAllBytes(Path.of(args[4]));
        ByteBuffer header=ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        int[] counts={1,5,3,header.getInt(88),header.getInt(80),header.getInt(56),header.getInt(64)};
        String[] relations={"method_defs","class_defs","field_defs","method_refs","field_refs","string_values","type_refs"};
        NativeEngine.EntityCandidate retained;
        try(var single=NativeEngine.openRawDex(dex,"single")){
            for(int r=0;r<relations.length;r++){
                var result=single.queryEntities(query(relations[r],"true"));
                check(result.relation==r&&result.executionStatus==0&&result.coverage==1&&result.candidateCount()==counts[r],"root "+relations[r]);
                check(result.queryId.startsWith(r==0?"query:v1:":"query:v2:"),"profile "+relations[r]);
                for(int i=0;i<result.candidateCount();i++){
                    var row=result.candidate(i);
                    check(row.relation==r&&row.sourceIndex==0&&row.inputIndex==0&&row.sourceSlot.equals("single")&&row.occurrenceId!=null,"origin "+relations[r]);
                    boolean member=r==0||r==2||r==3||r==4, method=r==0||r==3, typed=r==1||r==2||r==4||r==6;
                    check((row.owner!=null)==member&&(row.name!=null)==member&&(row.prototype!=null)==method&&
                          (row.typeDescriptor!=null)==typed&&(row.stringValue!=null)==(r==5),"applicable default projection "+relations[r]);
                }
            }
            var refs=single.queryEntities(query("field_refs","{\"has_local_definition\":false}"));
            check(refs.candidateCount()==1,"one external field");retained=refs.candidate(0);
            check(retained.name.equals("externalField")&&retained.definitionOffset==null&&retained.accessFlags==null&&retained.codeOffset==null,"unknown is null");
            var filtered=single.queryEntities(query("field_refs","{\"flags_contains\":0}"));
            check(filtered.candidateCount()==3&&filtered.unknownRows==1&&filtered.coverage==1,"unknown filter counted");
            var unknown=single.queryEntities(json("{\"schema_version\":1,\"relation\":\"field_refs\",\"where\":{\"all\":[{\"name\":\"externalField\"},{\"not\":{\"flags_contains\":0}}]},\"intent\":\"unique\"}"));
            check(unknown.candidateCount()==0&&unknown.unknownRows==1&&unknown.coverage==1&&unknown.decision==1,"NOT Unknown remains undetermined");
            var witness=single.queryEntities(json("{\"schema_version\":1,\"relation\":\"field_defs\",\"where\":{\"name\":\"shared\"},\"intent\":\"exists\"}"));
            check(witness.coverage==1&&witness.decision==3&&witness.candidateCount()>0,"exists witness despite incomplete scope");
            var limit=single.queryEntities(json("{\"schema_version\":1,\"relation\":\"field_defs\",\"max_results\":1}"));
            check(limit.executionStatus==4&&limit.coverage==1&&limit.reason==4&&limit.candidateCount()==1,"result limit remains partial failure");
            try{
                var budget=single.queryEntities(json("{\"schema_version\":1,\"relation\":\"field_defs\",\"max_work\":1}"));
                check(budget.executionStatus==4&&budget.coverage==1,"work budget remains partial failure");
            }catch(NativeEngine.NativeFailure e){check(e.status==4,"work budget native failure");}
            var method=single.queryEntities(query("method_defs","true")).candidate(0);
            var methodRef=single.queryEntities(query("method_refs","true")).candidate(0);
            check(method.codeOffset!=null&&method.codeOffset==0&&methodRef.definitionOffset!=null&&methodRef.codeOffset==null,"known no-code differs from ref unknown code");
            var projected=single.queryEntities(json("{\"schema_version\":1,\"relation\":\"field_refs\",\"where\":true,\"projection\":[\"identity\"]}"));
            check(projected.candidate(0).name==null&&projected.candidate(0).owner==null&&projected.candidate(0).typeDescriptor==null,"omitted projection null");
            var old=single.queryMethods(query("method_defs","true"));
            check(old.candidateCount()==1&&old.candidate(0).name.equals(method.name),"method-v1 remains usable");
            status(3,()->single.queryEntities(json("{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"field_refs\"}}")));
            status(3,()->single.queryEntities(json("{\"schema_version\":1,\"relation\":\"class_defs\",\"where\":{\"flags\":{\"domain\":\"reflection\",\"mode\":\"contains\",\"value\":1}},\"required_capabilities\":[\"reflection_flags_static\"]}")));
            status(3,()->single.queryEntities(json("{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"field_refs\",\"where\":{\"flags\":{\"domain\":\"reflection\",\"mode\":\"contains\",\"value\":1}}},\"intent\":\"enumerate\",\"required_capabilities\":[\"reflection_flags_static\",\"reflection_relational\"]}")));
            status(3,()->single.queryEntities(json("{\"schema_version\":1,\"relation\":\"field_refs\",\"scope\":{\"slots\":[\"single\"]}}")));
            status(3,()->single.queryEntities(json("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"using_strings\":{\"all\":[\"x\"]}}}")));
            status(4,()->single.queryEntities(json("{\"schema_version\":1,\"relation\":\"field_refs\",\"max_results\":4097}")));
        }
        check(retained.name.equals("externalField")&&retained.sourceSlot.equals("single")&&retained.definitionOffset==null,"copied values after close");
        try(var duplicate=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"a","b"})){
            var result=duplicate.queryEntities(query("field_defs","true"));
            check(result.candidateCount()==6,"duplicate occurrences preserved");
            var a=result.candidate(0);var b=result.candidate(3);
            check(a.localIndex==b.localIndex&&a.referenceIndex==b.referenceIndex&&!a.occurrenceId.equals(b.occurrenceId)&&a.sourceIndex==0&&b.sourceIndex==1,"not deduplicated by content");
            var unique=duplicate.queryEntities(json("{\"schema_version\":1,\"relation\":\"field_defs\",\"where\":{\"name\":\"shared\"},\"intent\":\"unique\"}"));
            check(unique.coverage==1&&unique.decision==2&&unique.reason==2,"multiple witnesses prove ambiguity");
        }
        try(var mixed=NativeEngine.openSources(new byte[][]{resource,apk},new String[]{"res","apk"},
                new int[]{NativeEngine.SOURCE_APK,NativeEngine.SOURCE_APK},new boolean[]{true,false})){
            var info=mixed.info();var result=mixed.queryEntities(query("method_defs","true"));
            check(info.inputCount()==2&&info.sourceCount()>0&&result.candidateCount()>0,"expanded APK");
            for(int i=0;i<result.candidateCount();i++){
                var row=result.candidate(i);var source=info.source(row.sourceIndex);
                check(row.inputIndex==1&&row.inputIndex==source.inputIndex&&row.sourceSlot.equals(source.slot)&&row.occurrenceId.equals(source.occurrenceId),"APK origin");
            }
        }
        try(var empty=NativeEngine.openSources(new byte[][]{resource},new String[]{"res"},new int[]{NativeEngine.SOURCE_APK},new boolean[]{true})){
            var result=empty.queryEntities(json("{\"schema_version\":1,\"relation\":\"class_defs\",\"intent\":\"exists\"}"));
            check(result.candidateCount()==0&&result.coverage==1&&result.decision==1,"empty scope cannot prove absence");
        }
        try(var utf=NativeEngine.openRawDex(unicode,"unicode")){
            var result=utf.queryEntities(query("string_values","{\"value\":{\"op\":\"exact\",\"u16\":[109,101,116,104,111,100,55357,56832]}}"));
            check(result.candidateCount()==1&&result.candidate(0).stringValue.equals("method\ud83d\ude00"),"UTF-16 copied");
        }
        try(var strings=NativeEngine.openRawDex(emptyAndNul,"strings")){
            var empty=strings.queryEntities(query("string_values","{\"value\":{\"op\":\"exact\",\"value\":\"\"}}"));
            check(empty.candidateCount()==1&&empty.candidate(0).stringValue!=null&&empty.candidate(0).stringValue.isEmpty()&&empty.candidate(0).name==null,"empty projected value differs from absent projection");
            var nul=strings.queryEntities(query("string_values","{\"value\":{\"op\":\"exact\",\"u16\":[38634,55357,56832,0,116,97,105,108]}}"));
            check(nul.candidateCount()==1&&nul.candidate(0).stringValue.equals("雪\ud83d\ude00\u0000tail"),"embedded NUL and surrogate pair copied");
        }
        var racing=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"a","b"});
        var field=NativeEngine.SourceSetSnapshot.class.getDeclaredField("token");field.setAccessible(true);long token=field.getLong(racing);
        var nativeQuery=NativeEngine.class.getDeclaredMethod("nativeQueryEntities",long.class,byte[].class,boolean.class);nativeQuery.setAccessible(true);
        var nativeClose=NativeEngine.class.getDeclaredMethod("nativeClose",long.class);nativeClose.setAccessible(true);
        var pool=Executors.newFixedThreadPool(2);var start=new CountDownLatch(1);
        try{
            var reader=pool.submit(()->{try{start.await();for(int i=0;i<50;i++)try{
                var result=(NativeEngine.EntityResult)nativeQuery.invoke(null,token,query("field_defs","true"),true);
                check(result.candidateCount()==6&&result.coverage==1,"native close race result");
            }catch(InvocationTargetException e){check(e.getCause() instanceof NativeEngine.NativeFailure&&((NativeEngine.NativeFailure)e.getCause()).status==7,"native close race status");break;}}
            catch(ReflectiveOperationException|InterruptedException e){throw new AssertionError(e);}});
            var closer=pool.submit(()->{try{start.await();nativeClose.invoke(null,token);}catch(ReflectiveOperationException|InterruptedException e){throw new AssertionError(e);}});
            start.countDown();reader.get();closer.get();
        }finally{racing.close();pool.shutdownNow();}
        System.out.println("PASS JNI direct entities, unknown/null, projection and origins");
    }
}
