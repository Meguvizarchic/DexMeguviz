package io.github.jichuo1.dexmeguviz;
import java.nio.file.*;
import java.util.*;

/** Host JVM/JNI exercise over a real D8 fixture; no Android or ART claim. */
public final class JniClassAnnotationGraphTest {
    static void check(boolean b,String why){if(!b)throw new AssertionError(why);}
    static ClassAnnotationGraphQuery query(EntityRelation relation,boolean owner,List<String> slots){
        var flags=new ReflectionFlags(8);
        var predicate=owner?GraphPredicate.Companion.reflectionOwnerFlags(RawFlagOperation.CONTAINS,flags):GraphPredicate.Companion.reflectionFlags(RawFlagOperation.CONTAINS,flags);
        return new ClassAnnotationGraphQuery(GraphExpression.Companion.scan(relation,predicate),QueryIntent.ENUMERATE,100,1000000L,slots);
    }
    static void verify(GraphResult out,int rows,int sources){
        check(out.queryId.startsWith("query:v20:")&&out.rowCount()==rows&&out.sourceCount()==sources,"profile/count");
        int details=0;for(int i=0;i<out.rowCount();i++){var row=out.row(i);for(int j=0;j<row.witnessCount();j++){var w=row.witness(j);if(w.classAnnotationFlags!=null){details++;check(w.kind==14&&w.classAnnotationFlags.sourceKind==3&&(w.classAnnotationFlags.projectedFlags&8)!=0&&w.sourceIndex<sources,"detail");}}}
        check(details==rows,"detail count");
    }
    public static void main(String[] a)throws Exception{
        byte[] dex=Files.readAllBytes(Path.of(a[0]));
        try(var one=NativeEngine.openRawDex(dex,"one")){
            var q=query(EntityRelation.CLASS_DEFS,false,null);verify(ClassAnnotationGraphExecution.INSTANCE.execute(one,q),3,1);
            try{one.queryGraph(q.toQueryIrJson().getBytes(java.nio.charset.StandardCharsets.UTF_8));throw new AssertionError("old wire accepted v20");}catch(NativeEngine.NativeFailure expected){check(expected.status==3,"old wire error");}
            verify(ClassAnnotationGraphExecution.INSTANCE.execute(one,query(EntityRelation.METHOD_DEFS,true,null)),3,1);
        }
        try(var both=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})){
            verify(ClassAnnotationGraphExecution.INSTANCE.execute(both,query(EntityRelation.CLASS_DEFS,false,null)),6,2);
            verify(ClassAnnotationGraphExecution.INSTANCE.execute(both,query(EntityRelation.CLASS_DEFS,false,List.of("one"))),3,2);
        }
        if(a.length>1){
            byte[] damaged=Files.readAllBytes(Path.of(a[1]));
            try(var snap=NativeEngine.openRawDex(damaged,"wrongtype")){
                var pred=GraphPredicate.Companion.reflectionFlags(RawFlagOperation.CONTAINS,new ReflectionFlags(0));
                var q=new ClassAnnotationGraphQuery(GraphExpression.Companion.scan(EntityRelation.CLASS_DEFS,pred),QueryIntent.ENUMERATE,100,1000000L,null);
                var out=ClassAnnotationGraphExecution.INSTANCE.execute(snap,q);
                check(out.unknownRows==1&&out.rowCount()==5,"unknown flags must not become raw fallback");
            }
        }
        System.out.println("PASS host Kotlin facade + JNI v20 static class and owner flags, source occurrences and old wire rejection");
    }
}
