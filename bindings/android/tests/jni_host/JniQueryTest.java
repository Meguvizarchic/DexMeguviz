package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public final class JniQueryTest {
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static byte[] json(String text){return text.getBytes(StandardCharsets.UTF_8);}
    private static String q(String intent,String name){return "{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\""+name+"\"},\"intent\":\""+intent+"\"}";}
    private static void failure(int status,Runnable work){try{work.run();throw new AssertionError("expected status "+status);}catch(NativeEngine.NativeFailure e){check(e.status==status,"status "+e.status);}}
    public static void main(String[] args)throws Exception{
        byte[] dex=Files.readAllBytes(Path.of(args[0]));
        NativeEngine.QueryResult copied;
        try(NativeEngine.Snapshot snapshot=NativeEngine.openRawDex(dex,"query")){
            copied=snapshot.queryMethods(json(q("unique","locate")));
            check(copied.executionStatus==0&&copied.coverage==1&&copied.decision==1,"unique must remain undetermined for incomplete scope");
            check(copied.candidateCount()==1&&copied.candidate(0).name.equals("locate")&&copied.queryId.startsWith("query:v1:"),"candidate and query identity");
            check(copied.snapshotId.equals(snapshot.info().snapshotId),"snapshot identity");
            var found=snapshot.queryMethods(json(q("exists","locate")));
            check(found.executionStatus==0&&found.coverage==1&&found.decision==3&&found.candidateCount()==1,"exists witness from incomplete scope");
            var absent=snapshot.queryMethods(json(q("exists","absent")));
            check(absent.executionStatus==0&&absent.coverage==1&&absent.decision==1&&absent.candidateCount()==0,"absence must remain undetermined");
            var limited=snapshot.queryMethods(json("{\"schema_version\":1,\"relation\":\"method_defs\",\"max_results\":1}"));
            check(limited.executionStatus==4&&limited.coverage==1&&limited.reason==4&&limited.candidateCount()==1,"result limit is not complete success");
            var projected=snapshot.queryMethods(json("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"locate\"},\"projection\":[\"name\"]}"));
            check(projected.candidateCount()==1&&projected.projectionMask==2&&projected.candidate(0).owner==null&&projected.candidate(0).prototype==null&&projected.candidate(0).name.equals("locate"),"projection preserves absent values");
            failure(3,()->snapshot.queryMethods(json("{\"schema_version\":1,\"relation\":\"class_defs\"}")));
            failure(3,()->snapshot.queryMethods(json("{\"schema_version\":1,\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"query\"]}}")));
            failure(4,()->snapshot.queryMethods(json("{\"schema_version\":1,\"relation\":\"method_defs\",\"max_work\":100000001}")));
            failure(4,()->snapshot.queryMethods(new byte[65537]));
            try{snapshot.queryMethods(null);throw new AssertionError("null query");}catch(NullPointerException expected){}
        }
        check(copied.candidate(0).name.equals("locate")&&copied.snapshotId.startsWith("snapshot:v2:"),"result owns copies after close");
        NativeEngine.Snapshot shared=NativeEngine.openRawDex(dex,"concurrent-query");
        var pool=Executors.newFixedThreadPool(2);var start=new CountDownLatch(1);
        try{
            Future<?> reader=pool.submit(()->{try{start.await();for(int i=0;i<50;i++)try{var r=shared.queryMethods(json(q("exists","locate")));check(r.coverage==1,"race coverage");}catch(IllegalStateException closed){break;}}catch(InterruptedException e){throw new AssertionError(e);}});
            Future<?> closer=pool.submit(()->{try{start.await();shared.close();}catch(InterruptedException e){throw new AssertionError(e);}});
            start.countDown();reader.get();closer.get();
        }finally{shared.close();pool.shutdownNow();}
        // Bypass Java synchronization to exercise the native shared owner.
        NativeEngine.Snapshot raw=NativeEngine.openRawDex(dex,"native-query-race");
        var tokenField=NativeEngine.Snapshot.class.getDeclaredField("token");tokenField.setAccessible(true);long token=tokenField.getLong(raw);
        var query=NativeEngine.class.getDeclaredMethod("nativeQueryMethods",long.class,byte[].class);query.setAccessible(true);
        var close=NativeEngine.class.getDeclaredMethod("nativeClose",long.class);close.setAccessible(true);
        var rawPool=Executors.newFixedThreadPool(2);var rawStart=new CountDownLatch(1);
        try{
            Future<?> reader=rawPool.submit(()->{try{rawStart.await();for(int i=0;i<50;i++){
                try{var r=(NativeEngine.QueryResult)query.invoke(null,token,json(q("exists","locate")));check(r.coverage==1,"native race result");}
                catch(InvocationTargetException e){check(e.getCause() instanceof NativeEngine.NativeFailure&&((NativeEngine.NativeFailure)e.getCause()).status==7,"native race failure");break;}
            }}catch(ReflectiveOperationException|InterruptedException e){throw new AssertionError(e);}});
            Future<?> closer=rawPool.submit(()->{try{rawStart.await();close.invoke(null,token);}catch(ReflectiveOperationException|InterruptedException e){throw new AssertionError(e);}});
            rawStart.countDown();reader.get();closer.get();
        }finally{raw.close();rawPool.shutdownNow();}
        System.out.println("PASS JNI method-v1 query, incomplete scope, copied result, errors and close race");
    }
}
