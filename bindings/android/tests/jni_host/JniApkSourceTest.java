package io.github.jichuo1.dexmeguviz;

import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/** Fixed synthetic APKs and explicit empty-input / expansion-boundary checks. */
public final class JniApkSourceTest {
    private static void check(boolean value,String what) { if (!value) throw new AssertionError(what); }
    private static void failure(int expected,Runnable f) { try { f.run(); throw new AssertionError("expected failure"); } catch (NativeEngine.NativeFailure e) { check(e.status==expected,"status "+e.status); } }
    private static void invalid(Runnable f) { try { f.run(); throw new AssertionError("invalid accepted"); } catch (IllegalArgumentException expected) {} }
    private static byte[] query(String intent,String name) { return ("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\""+name+"\"},\"intent\":\""+intent+"\"}").getBytes(StandardCharsets.UTF_8); }
    private static String digest(byte[] value) throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));}
    private static String frame(String value) {return value.getBytes(StandardCharsets.UTF_8).length+":"+value;}
    private static String content(byte[] value) throws Exception {return "sha256:raw-dex:v1:"+value.length+":"+digest(value);}
    private static String occurrence(String slot,String entry,String content) throws Exception {
        String value="dmg:occurrence:v2:"+frame("android-jni")+frame(entry==null?"raw-input":"archive-entry")+
                frame(slot)+frame(entry==null?"raw-dex":"apk")+frame(entry==null?"":entry)+frame(content);
        return "occurrence:v2:"+digest(value.getBytes(StandardCharsets.UTF_8));
    }
    private static String snapshot(NativeEngine.SourceSetInfo info) throws Exception {
        StringBuilder value=new StringBuilder("dmg:snapshot:source-set-v1:").append(frame("android-jni")).append(frame("incomplete")).append(frame(Integer.toString(info.inputCount())));
        for(int i=0;i<info.inputCount();i++) {var in=info.input(i);value.append(frame(in.slot)).append(frame(in.format==NativeEngine.SOURCE_RAW_DEX?"raw-dex":"apk"))
                .append(frame(Integer.toString(in.format))).append(frame(in.allowNoDex?"1":"0")).append(frame(in.contentId));}
        value.append(frame(Integer.toString(info.sourceCount())));
        for(int i=0;i<info.sourceCount();i++)value.append(frame(info.source(i).occurrenceId));
        return "snapshot:v2:"+digest(value.toString().getBytes(StandardCharsets.UTF_8));
    }
    private static Map<String,byte[]> entries(byte[] apk) throws Exception {
        Map<String,byte[]> result=new HashMap<>();try(ZipInputStream stream=new ZipInputStream(new ByteArrayInputStream(apk))) {
            for(ZipEntry entry;(entry=stream.getNextEntry())!=null;) {check(!result.containsKey(entry.getName()),"duplicate sample entry");result.put(entry.getName(),stream.readAllBytes());}
        } return result;
    }
    private static byte[] manyDex(byte[] dex,int count) throws Exception {
        ByteArrayOutputStream result=new ByteArrayOutputStream();
        try(ZipOutputStream zip=new ZipOutputStream(result)) {
            for(int i=1;i<=count;i++) { zip.putNextEntry(new ZipEntry(i==1?"classes.dex":"classes"+i+".dex")); zip.write(dex); zip.closeEntry(); }
        }
        return result.toByteArray();
    }
    public static void main(String[] args) throws Exception {
        check(args.length==1,"fixture directory argument");Path fixtures=Path.of(args[0]);
        byte[] dex=Files.readAllBytes(fixtures.resolve("raw-a.dex"));
        byte[] apk=Files.readAllBytes(fixtures.resolve("reverse-stored.apk"));
        byte[] resource=Files.readAllBytes(fixtures.resolve("resource-only.apk"));
        byte[] corrupt=Files.readAllBytes(fixtures.resolve("one-corrupt-dex.apk"));
        byte[] badCrc=Files.readAllBytes(fixtures.resolve("bad-crc.apk"));
        byte[] duplicate=Files.readAllBytes(fixtures.resolve("duplicate-entry.apk"));
        byte[] noncanonical=Files.readAllBytes(fixtures.resolve("classes1-only.apk"));
        String apkSha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(apk));
        String resourceSha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(resource));
        Map<String,byte[]> apkEntries=entries(apk);
        final int raw=NativeEngine.SOURCE_RAW_DEX,zip=NativeEngine.SOURCE_APK;
        NativeEngine.SourceSetInfo saved;
        try(var set=NativeEngine.openSources(new byte[][]{dex,apk,resource,dex},new String[]{"raw","base","resource","split"},new int[]{raw,zip,zip,raw},new boolean[]{false,false,true,false})) {
            var info=set.info();saved=info;
            check(!info.sourceScopeComplete&&info.inputCount()==4&&info.sourceCount()==5,"expanded counts and incomplete scope");
            check(info.input(0).format==raw&&!info.input(0).containerMetadataChecked,"raw input has no APK container");
            check(info.input(1).inputIndex==1&&info.input(1).format==zip&&info.input(1).sourceCount==3&&info.input(1).sourceSha256.equals(apkSha)&&info.input(1).containerMetadataChecked,"APK input identity");
            check(info.input(2).allowNoDex&&info.input(2).sourceCount==0&&info.input(2).sourceSha256.equals(resourceSha),"resource-only input identity");
            check(info.input(0).contentId.equals(content(dex))&&info.input(3).contentId.equals(content(dex)),"raw input content identities");
            check(info.input(1).contentId.equals("sha256:apk:v1:"+apk.length+":"+apkSha)&&info.input(2).contentId.equals("sha256:apk:v1:"+resource.length+":"+resourceSha),"APK input content identities");
            check(info.source(0).inputIndex==0&&info.source(0).archiveEntryName==null&&info.source(0).archiveEntryIndex==-1,"raw origin");
            check(info.source(0).contentId.equals(content(dex))&&info.source(0).occurrenceId.equals(occurrence("raw",null,content(dex))),"independent raw identity");
            String[] names={"classes.dex","classes2.dex","classes10.dex"};int[] central={3,2,0};
            for(int i=0;i<3;i++) {var s=info.source(i+1);check(s.sourceIndex==i+1&&s.inputIndex==1&&s.slot.equals("base")&&s.archiveEntryName.equals(names[i])&&s.archiveEntryIndex==central[i],"numeric DEX order and original central index "+i);
                String expectedContent=content(apkEntries.get(names[i]));check(s.contentId.equals(expectedContent)&&s.occurrenceId.equals(occurrence("base",names[i],expectedContent)),"independent APK occurrence "+i);}
            check(info.source(4).sourceIndex==4&&info.source(4).inputIndex==3&&info.source(4).slot.equals("split"),"noncontiguous input/source origin");
            check(info.source(4).contentId.equals(content(dex))&&info.source(4).occurrenceId.equals(occurrence("split",null,content(dex))),"independent split identity");
            check(info.snapshotId.equals(snapshot(info)),"independent snapshot identity");
            var rows=set.queryMethods(query("enumerate","locate"));check(rows.executionStatus==0&&rows.coverage==1&&rows.candidateCount()==5,"expanded results");
            for(int i=0;i<5;i++) { var row=rows.candidate(i);var s=info.source(i);check(row.sourceIndex==s.sourceIndex&&row.inputIndex==s.inputIndex&&row.sourceSlot.equals(s.slot)&&row.occurrenceId.equals(s.occurrenceId),"expanded candidate provenance "+i); }
        }
        check(saved.input(2).sourceSha256.equals(resourceSha)&&saved.source(3).archiveEntryName.equals("classes10.dex"),"copied metadata survives close");
        try(var empty=NativeEngine.openSources(new byte[][]{resource},new String[]{"resource"},new int[]{zip},new boolean[]{true})) {
            check(empty.info().inputCount()==1&&empty.info().sourceCount()==0&&empty.info().input(0).sourceCount==0,"all-resource snapshot");
            var result=empty.queryMethods(query("exists","locate"));check(result.executionStatus==0&&result.coverage==1&&result.candidateCount()==0&&result.decision==1,"empty incomplete scope cannot prove absence");
        }
        try(var legacy=NativeEngine.openRawDexSet(new byte[][]{dex},new String[]{"same"});
            var typed=NativeEngine.openSources(new byte[][]{dex},new String[]{"same"},new int[]{raw},new boolean[]{false})) {
            check(legacy.info().snapshotId.equals(typed.info().snapshotId),"raw identity compatibility");
        }
        invalid(()->NativeEngine.openSources(new byte[][]{dex},new String[]{"s"},new int[]{0},new boolean[]{false}));
        invalid(()->NativeEngine.openSources(new byte[][]{dex},new String[]{"s"},new int[]{raw},new boolean[]{true}));
        invalid(()->NativeEngine.openSources(new byte[][]{dex},new String[]{"s"},new int[]{raw},new boolean[]{}));
        failure(2,()->NativeEngine.openSources(new byte[][]{resource},new String[]{"s"},new int[]{zip},new boolean[]{false}));
        for(byte[] bad : new byte[][]{badCrc,duplicate,noncanonical})
            failure(2,()->NativeEngine.openSources(new byte[][]{dex,bad},new String[]{"good","bad"},new int[]{raw,zip},new boolean[]{false,false}));
        for(int i=0;i<80;i++) failure(2,()->NativeEngine.openSources(new byte[][]{dex,corrupt},new String[]{"good","bad"},new int[]{raw,zip},new boolean[]{false,false}));
        byte[] sixtyFour=manyDex(dex,64),sixtyFive=manyDex(dex,65);
        try(var full=NativeEngine.openSources(new byte[][]{sixtyFour},new String[]{"full"},new int[]{zip},new boolean[]{false})) {check(full.info().sourceCount()==64&&full.info().inputCount()==1,"64 expanded sources");}
        failure(4,()->NativeEngine.openSources(new byte[][]{sixtyFive},new String[]{"too-many"},new int[]{zip},new boolean[]{false}));
        byte[] inflated=manyDex(new byte[16*1024*1024+1],1);
        check(inflated.length<16*1024*1024,"compressed limit sample");
        failure(4,()->NativeEngine.openSources(new byte[][]{inflated},new String[]{"inflate"},new int[]{zip},new boolean[]{false}));
        var held=new ArrayList<NativeEngine.SourceSetSnapshot>();try {
            for(int i=0;i<64;i++)held.add(NativeEngine.openSources(new byte[][]{resource},new String[]{"s"+i},new int[]{zip},new boolean[]{true}));
            failure(4,()->NativeEngine.openSources(new byte[][]{resource},new String[]{"full"},new int[]{zip},new boolean[]{true}));
        } finally {for(var s:held)s.close();}
        System.out.println("PASS APK source expansion, input identities, empty resources, provenance and rollback");
    }
}
