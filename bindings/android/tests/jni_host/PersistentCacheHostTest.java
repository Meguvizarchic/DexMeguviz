package io.github.jichuo1.dexmeguviz;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/** Opt-in host JNI only; no device, ART, APK-signature or performance claim. */
public final class PersistentCacheHostTest {
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static void same(NativeEngine.QueryResult a,NativeEngine.QueryResult b){
        check(a.executionStatus==b.executionStatus&&a.coverage==b.coverage&&a.decision==b.decision&&a.reason==b.reason&&a.visitedMethods==b.visitedMethods&&a.totalMethods==b.totalMethods&&a.unknownRows==b.unknownRows&&a.candidateCount()==b.candidateCount()&&Objects.equals(a.queryId,b.queryId)&&Objects.equals(a.snapshotId,b.snapshotId),"result metadata mismatch");
        for(int i=0;i<a.candidateCount();++i){var x=a.candidate(i);var y=b.candidate(i);check(x.methodIndex==y.methodIndex&&x.accessFlags==y.accessFlags&&x.declarationOffset==y.declarationOffset&&x.codeOffset==y.codeOffset&&x.sourceIndex==y.sourceIndex&&x.inputIndex==y.inputIndex&&Objects.equals(x.sourceSlot,y.sourceSlot)&&Objects.equals(x.occurrenceId,y.occurrenceId)&&Objects.equals(x.owner,y.owner)&&Objects.equals(x.name,y.name)&&Objects.equals(x.prototype,y.prototype),"candidate mismatch");}
    }
    public static void main(String[] args)throws Exception {
        check(args.length==3,"arguments");byte[] dex=Files.readAllBytes(Path.of(args[0])),other=Files.readAllBytes(Path.of(args[1]));Path base=Path.of(args[2]);Files.createDirectory(base);
        byte[] query=("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"using_strings\":{\"all\":[{\"op\":\"exact\",\"value\":\"code-use-q03\"}]}},\"intent\":\"enumerate\",\"max_results\":100}").getBytes(StandardCharsets.UTF_8);
        try(NativeEngine.Snapshot snap=NativeEngine.openRawDex(dex,"base")){
            var direct=snap.queryMethods(query);check(direct.executionStatus==0&&direct.coverage==1&&direct.candidateCount()==1,"direct fixture");
            File location=base.resolve("\u7f13\u5b58").toFile();
            try(PersistentCacheBridge cache=PersistentCacheBridge.open(snap,location)){
                var cold=cache.queryMethods(query);var first=cache.statistics();var warm=cache.queryMethods(query);var second=cache.statistics();same(direct,cold);same(direct,warm);
                check(first.length==7&&second.length==7&&second[0]>first[0],"warm persistent facts not observed");
            }
            try(PersistentCacheBridge limited=PersistentCacheBridge.open(snap,base.resolve("write-fallback").toFile(),new PersistentCacheBridge.Limits(1,0,0,0))){same(direct,limited.queryMethods(query));check(limited.statistics()[5]>0,"failed publication did not fall back");}
            try{PersistentCacheBridge.open(snap,new File("x".repeat(5000)));throw new AssertionError("overlong path accepted");}catch(IllegalArgumentException expectedPath){}
            try(PersistentCacheBridge multi=PersistentCacheBridge.open(snap,base.resolve("concurrent").toFile())){
                CountDownLatch start=new CountDownLatch(1);AtomicInteger failures=new AtomicInteger();Thread[] workers=new Thread[4];
                for(int i=0;i<workers.length;i++){workers[i]=new Thread(()->{try{start.await();for(int n=0;n<3;n++)same(direct,multi.queryMethods(query));}catch(Throwable e){e.printStackTrace();failures.incrementAndGet();}});workers[i].start();}
                start.countDown();for(Thread t:workers)t.join();check(failures.get()==0&&multi.statistics()[0]>0,"concurrent cache use");
            }
        }
        NativeEngine.SourceSetSnapshot set=NativeEngine.openRawDexSet(new byte[][]{dex,other},new String[]{"base","split"});
        PersistentCacheBridge cache=PersistentCacheBridge.open(set,base.resolve("source-set").toFile());var expected=set.queryMethods(query);same(expected,cache.queryMethods(query));same(expected,cache.queryMethods(query));check(cache.statistics()[0]>0,"SourceSet hit");set.close();
        try{cache.queryMethods(query);throw new AssertionError("closed source accepted");}catch(NativeEngine.NativeFailure failure){check(failure.status==7,"closed source status");}cache.close();
        try{cache.queryMethods(query);throw new AssertionError("closed cache accepted");}catch(IllegalStateException expectedClosed){}
        try{PersistentCacheBridge.open(set,base.resolve("bad").toFile());throw new AssertionError("closed source opened");}catch(NativeEngine.NativeFailure failure){check(failure.status==7,"closed open status");}
        try{new PersistentCacheBridge.Limits(-1,0,0,0);throw new AssertionError("invalid limit accepted");}catch(IllegalArgumentException expectedInvalid){}
        NativeEngine.Snapshot race=NativeEngine.openRawDex(dex,"race");PersistentCacheBridge racing=PersistentCacheBridge.open(race,base.resolve("close-race").toFile());
        CountDownLatch ready=new CountDownLatch(4),go=new CountDownLatch(1);AtomicInteger raceErrors=new AtomicInteger();Thread[] racingThreads=new Thread[4];
        for(int i=0;i<racingThreads.length;i++){racingThreads[i]=new Thread(()->{ready.countDown();try{go.await();var result=racing.queryMethods(query);check(result.executionStatus==0,"admitted race result");}catch(NativeEngine.NativeFailure f){if(f.status!=7)raceErrors.incrementAndGet();}catch(Throwable t){raceErrors.incrementAndGet();}});racingThreads[i].start();}
        ready.await();go.countDown();race.close();for(Thread t:racingThreads)t.join();check(raceErrors.get()==0,"snapshot close race");racing.close();
        System.out.println("PASS optional persistent method JNI cold/warm, SourceSet, UTF-8 directory, write fallback, threads, close and limits");
    }
}
