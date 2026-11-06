package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.lang.reflect.InvocationTargetException;

public final class JniSourceSetTest {
    private static void check(boolean value,String text){if(!value)throw new AssertionError(text);}
    private static void status(int expected,Runnable action){try{action.run();throw new AssertionError("expected NativeFailure");}catch(NativeEngine.NativeFailure e){check(e.status==expected,"status "+e.status);}}
    private static void invalid(Runnable action){try{action.run();throw new AssertionError("invalid accepted");}catch(IllegalArgumentException expected){}}
    private static byte[] query(String intent,String name){return ("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\""+name+"\"},\"intent\":\""+intent+"\"}").getBytes(StandardCharsets.UTF_8);}
    public static void main(String[] args)throws Exception{
        byte[] dex=Files.readAllBytes(Path.of(args[0])),other=Files.readAllBytes(Path.of(args[1]));
        var sha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(dex));
        try(var one=NativeEngine.openRawDex(dex,"same");var set=NativeEngine.openRawDexSet(new byte[][]{dex},new String[]{"same"})){
            check(one.info().snapshotId.equals(set.info().snapshotId),"single snapshot identity changed");
        }
        NativeEngine.QueryResult copied;
        NativeEngine.SourceSetInfo info;
        try(var set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"base","split"})){
            info=set.info();check(!info.sourceScopeComplete&&info.sourceCount()==2,"scope and source count");
            var a=info.source(0);var b=info.source(1);
            check(a.sourceIndex==0&&a.inputIndex==0&&b.sourceIndex==1&&b.inputIndex==1&&a.slot.equals("base")&&b.slot.equals("split"),"ordered origins");
            check(a.sourceSha256.equals(sha)&&b.sourceSha256.equals(sha)&&a.contentId.equals(b.contentId)&&!a.occurrenceId.equals(b.occurrenceId),"duplicate content occurrences");
            copied=set.queryMethods(query("enumerate","locate"));check(copied.coverage==1&&copied.candidateCount()==2&&copied.snapshotId.equals(info.snapshotId),"two occurrence rows");
            for(int i=0;i<2;i++){var row=copied.candidate(i);var source=info.source(i);check(row.sourceIndex==i&&row.inputIndex==i&&row.sourceSlot.equals(source.slot)&&row.occurrenceId.equals(source.occurrenceId)&&row.name.equals("locate"),"candidate origin "+i);}
            var unique=set.queryMethods(query("unique","locate"));check(unique.coverage==1&&unique.decision==2&&unique.reason==2,"ambiguous unique");
            var absent=set.queryMethods(query("exists","absent"));check(absent.coverage==1&&absent.decision==1&&absent.candidateCount()==0,"incomplete absence");
        }
        check(copied.candidate(1).sourceSlot.equals("split")&&info.source(1).sourceSha256.equals(sha),"copies survive close");
        try(var reversed=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"split","base"})){
            var r=reversed.info();check(!r.snapshotId.equals(info.snapshotId)&&r.source(0).occurrenceId.equals(info.source(1).occurrenceId)&&r.source(1).occurrenceId.equals(info.source(0).occurrenceId),"order and stable occurrence");
        }
        try(var mixed=NativeEngine.openRawDexSet(new byte[][]{dex,other},new String[]{"base","other"})){
            var r=mixed.info();check(r.sourceCount()==2&&!r.source(0).contentId.equals(r.source(1).contentId),"distinct DEX inputs");
            var found=mixed.queryMethods(query("enumerate","uses"));check(found.candidateCount()==1&&found.candidate(0).sourceIndex==1&&found.candidate(0).sourceSlot.equals("other")&&found.candidate(0).occurrenceId.equals(r.source(1).occurrenceId),"candidate from second distinct DEX");
        }
        byte[][] eight=new byte[8][];String[] eightSlots=new String[8];for(int i=0;i<8;i++){eight[i]=dex;eightSlots[i]="eight."+i;}
        try(var full=NativeEngine.openRawDexSet(eight,eightSlots)){check(full.info().sourceCount()==8&&full.queryMethods(query("enumerate","locate")).candidateCount()==8,"eight-source boundary");}
        invalid(()->NativeEngine.openRawDexSet(new byte[][]{},new String[]{}));
        invalid(()->NativeEngine.openRawDexSet(new byte[][]{dex},new String[]{}));
        invalid(()->NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"dup","dup"}));
        invalid(()->NativeEngine.openRawDexSet(new byte[9][],new String[9]));
        try{NativeEngine.openRawDexSet(new byte[][]{dex,null},new String[]{"a","b"});throw new AssertionError("null source");}catch(NullPointerException expected){}
        status(4,()->NativeEngine.openRawDexSet(new byte[][]{new byte[16*1024*1024],new byte[1]},new String[]{"a","b"}));
        for(int i=0;i<80;i++)status(2,()->NativeEngine.openRawDexSet(new byte[][]{dex,new byte[0]},new String[]{"good","bad"}));
        var held=new ArrayList<NativeEngine.SourceSetSnapshot>();try{
            for(int i=0;i<64;i++)held.add(NativeEngine.openRawDexSet(new byte[][]{dex},new String[]{"s"+i}));
            status(4,()->NativeEngine.openRawDexSet(new byte[][]{dex},new String[]{"full"}));
        }finally{for(var s:held)s.close();}
        var shared=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"a","b"});var pool=Executors.newFixedThreadPool(2);var start=new CountDownLatch(1);
        try{
            Future<?> reader=pool.submit(()->{try{start.await();for(int i=0;i<50;i++)try{check(shared.queryMethods(query("exists","locate")).coverage==1,"race");}catch(IllegalStateException closed){break;}}catch(InterruptedException e){throw new AssertionError(e);}});
            Future<?> closer=pool.submit(()->{try{start.await();shared.close();}catch(InterruptedException e){throw new AssertionError(e);}});
            start.countDown();reader.get();closer.get();
        }finally{shared.close();pool.shutdownNow();}
        var raw=NativeEngine.openRawDexSet(new byte[][]{dex,other},new String[]{"a","b"});
        var tokenField=NativeEngine.SourceSetSnapshot.class.getDeclaredField("token");tokenField.setAccessible(true);long token=tokenField.getLong(raw);
        var rawQuery=NativeEngine.class.getDeclaredMethod("nativeQuerySourceSetMethods",long.class,byte[].class);rawQuery.setAccessible(true);
        var rawClose=NativeEngine.class.getDeclaredMethod("nativeClose",long.class);rawClose.setAccessible(true);
        var rawPool=Executors.newFixedThreadPool(2);var rawStart=new CountDownLatch(1);
        try{
            Future<?> reader=rawPool.submit(()->{try{rawStart.await();for(int i=0;i<50;i++)try{
                var r=(NativeEngine.QueryResult)rawQuery.invoke(null,token,query("exists","uses"));check(r.coverage==1&&r.candidate(0).sourceIndex==1,"native race origin");
            }catch(InvocationTargetException e){check(e.getCause() instanceof NativeEngine.NativeFailure&&((NativeEngine.NativeFailure)e.getCause()).status==7,"native race failure");break;}}
            catch(ReflectiveOperationException|InterruptedException e){throw new AssertionError(e);}});
            Future<?> closer=rawPool.submit(()->{try{rawStart.await();rawClose.invoke(null,token);}catch(ReflectiveOperationException|InterruptedException e){throw new AssertionError(e);}});
            rawStart.countDown();reader.get();closer.get();
        }finally{raw.close();rawPool.shutdownNow();}
        System.out.println("PASS ordered multi-DEX, occurrence/origin, incomplete scope, rollback and close");
    }
}
