import io.github.jichuo1.dexmeguviz.NativeEngine;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

public final class MethodStreamTest {
    static void check(boolean ok,String what){if(!ok)throw new AssertionError(what);}
    static byte[] q(String text){return text.getBytes(StandardCharsets.UTF_8);}
    static void same(NativeEngine.QueryResult a,NativeEngine.QueryResult b){
        check(a.executionStatus==b.executionStatus&&a.coverage==b.coverage&&a.decision==b.decision&&a.reason==b.reason&&a.visitedMethods==b.visitedMethods&&a.totalMethods==b.totalMethods&&a.unknownRows==b.unknownRows&&a.projectionMask==b.projectionMask,"outcome");
        check(a.queryId.equals(b.queryId)&&a.snapshotId.equals(b.snapshotId)&&a.candidateCount()==b.candidateCount(),"identity/count");
        for(int i=0;i<a.candidateCount();++i){var x=a.candidate(i);var y=b.candidate(i);check(x.methodIndex==y.methodIndex&&x.accessFlags==y.accessFlags&&x.declarationOffset==y.declarationOffset&&x.codeOffset==y.codeOffset&&Objects.equals(x.owner,y.owner)&&Objects.equals(x.name,y.name)&&Objects.equals(x.prototype,y.prototype),"candidate");}
    }
    public static void main(String[] args)throws Exception{
        byte[] a=Files.readAllBytes(Path.of(args[0])), b=Files.readAllBytes(Path.of(args[1]));
        byte[][] queries={q("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"second\"}}"),q("{\"schema_version\":1,\"relation\":\"method_defs\",\"intent\":\"exists\",\"where\":{\"name\":\"absent\"}}")};
        NativeEngine.QueryResult retained;
        try(var session=NativeEngine.openMethodStream(queries,32L<<20,256L<<20)){
            for(byte[] dex:new byte[][]{a,b,a}){
                try(var s=session.openRawDex(dex,"slot");var old=NativeEngine.openRawDex(dex,"slot")){
                    for(int i=0;i<queries.length;++i)same(session.queryMethods(s,i),old.queryMethods(queries[i]));
                }
            }
            var s=session.openRawDex(a,"slot");retained=session.queryMethods(s,0);
            try(var foreign=NativeEngine.openRawDex(a,"slot")){try{session.queryMethods(foreign,0);throw new AssertionError("foreign engine accepted");}catch(NativeEngine.NativeFailure expected){check(expected.status==1,"foreign status");}}
            try{session.queryMethods(s,9);throw new AssertionError("invalid query index accepted");}catch(NativeEngine.NativeFailure expected){check(expected.status==1,"index status");}
            s.close();try{session.queryMethods(s,0);throw new AssertionError("closed snapshot accepted");}catch(IllegalStateException expected){}
        }
        check(retained.snapshotId.startsWith("snapshot:v2:"),"retained copy");
        var session=NativeEngine.openMethodStream(queries,32L<<20,256L<<20);
        var afterSession=session.openRawDex(a,"slot");session.close();
        check(afterSession.info().sourceBytes==a.length,"snapshot after stream close");
        check(afterSession.queryMethods(queries[0]).snapshotId.equals(afterSession.info().snapshotId),"independent query after stream close");
        try{session.queryMethods(afterSession,0);throw new AssertionError("closed stream accepted");}catch(IllegalStateException expected){}
        afterSession.close();
        try{NativeEngine.openMethodStream(new byte[][]{q("{\"schema_version\":1,\"relation\":\"class_defs\"}")},32L<<20,256L<<20);throw new AssertionError("unsupported query accepted");}catch(NativeEngine.NativeFailure expected){check(expected.status==3,"unsupported profile");}
        System.out.println("PASS reusable plans, streaming snapshots, results, ownership and profile checks");
    }
}
