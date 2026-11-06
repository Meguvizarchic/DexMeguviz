package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

/** Deterministic wire dump for an independent raw-byte entity oracle. */
public final class JniEntityDump {
    private static String text(String value){return value==null?"~":Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_16LE));}
    private static String number(Long value){return value==null?"~":value.toString();}
    public static void main(String[] args)throws Exception{
        byte[] dex=Files.readAllBytes(Path.of(args[0]));
        String[] relation={"method_defs","class_defs","field_defs","method_refs","field_refs","string_values","type_refs"};
        try(var set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"base","split"})){
            for(int r=0;r<relation.length;r++){
                byte[] json=("{\"schema_version\":1,\"relation\":\""+relation[r]+"\",\"where\":true,\"intent\":\"enumerate\"}").getBytes(StandardCharsets.UTF_8);
                var result=set.queryEntities(json);
                System.out.println("H\t"+r+"\t"+result.queryId+"\t"+result.executionStatus+"\t"+result.coverage+"\t"+result.decision+"\t"+result.reason+"\t"+result.unknownRows+"\t"+result.candidateCount());
                for(int i=0;i<result.candidateCount();i++){
                    var c=result.candidate(i);
                    System.out.println("R\t"+r+"\t"+c.sourceIndex+"\t"+c.inputIndex+"\t"+c.localIndex+"\t"+c.referenceIndex+"\t"+c.recordOffset+"\t"+
                        number(c.definitionOffset)+"\t"+number(c.accessFlags)+"\t"+number(c.codeOffset)+"\t"+
                        text(c.owner)+"\t"+text(c.name)+"\t"+text(c.prototype)+"\t"+text(c.typeDescriptor)+"\t"+text(c.stringValue)+"\t"+
                        c.sourceSlot+"\t"+c.occurrenceId);
                }
            }
        }
    }
}
