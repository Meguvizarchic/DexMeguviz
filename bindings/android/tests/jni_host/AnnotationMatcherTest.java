package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;

public final class AnnotationMatcherTest {
    static void check(boolean ok,String label) { if(!ok) throw new AssertionError(label); }
    static void fails(Class<? extends Throwable> type,Runnable f) {
        try { f.run(); } catch(Throwable t) { if(type.isInstance(t)) return; throw t; }
        throw new AssertionError("expected "+type.getName());
    }
    public static void main(String[] args)throws Exception {
        byte[] dex=Files.readAllBytes(Path.of(args[0]));
        var al=new Annotations.Limits(256,1000000,100000,10000);
        var vl=new EncodedValue.Limits(1024,100,20);
        final String descriptor="Lfixture/Complex;";
        AnnotationResult held;
        try(var set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})) {
            held=Annotations.collect(set,1,Annotations.Target.classType(2),al);
            check(held.sourceIndex==1 && held.itemCount()==2,"source and annotation count");
            var item=held.item(0);
            check(AnnotationMatcher.metadata(item,descriptor,1)==AnnotationMatcher.MATCH,"metadata");
            check(AnnotationMatcher.metadata(item,descriptor,0)==AnnotationMatcher.NO_MATCH,"visibility");
            check(AnnotationMatcher.metadata(item,"Lother;",-1)==AnnotationMatcher.NO_MATCH,"descriptor");
            check(AnnotationMatcher.scalar(item,descriptor,1,"n",EncodedValue.INT,-7,10,vl)==AnnotationMatcher.MATCH,"integer match");
            check(AnnotationMatcher.scalar(item,descriptor,1,"n",EncodedValue.INT,7,10,vl)==AnnotationMatcher.NO_MATCH,"integer mismatch");
            check(AnnotationMatcher.scalar(item,descriptor,1,"n",EncodedValue.LONG,-7,10,vl)==AnnotationMatcher.NO_MATCH,"kind mismatch");
            check(AnnotationMatcher.scalar(item,descriptor,1,"absent",EncodedValue.INT,0,10,vl)==AnnotationMatcher.UNKNOWN,"missing might use default");
            check(AnnotationMatcher.scalar(item,descriptor,1,"str",EncodedValue.STRING,42,10,vl)==AnnotationMatcher.MATCH,"source local index");
            String expected=DexSourceExport.stringAt(set,1,42,1000);
            AnnotationMatcher.Resolver resolver=(k,i)-> k==EncodedValue.STRING ? DexSourceExport.stringAt(set,1,i,1000) : DexSourceExport.typeAt(set,1,i,1000);
            check(AnnotationMatcher.text(item,descriptor,1,"str",EncodedValue.STRING,expected,resolver,10,vl)==AnnotationMatcher.MATCH,"string resolution");
            check(AnnotationMatcher.text(item,descriptor,1,"str",EncodedValue.STRING,expected+"!",resolver,10,vl)==AnnotationMatcher.NO_MATCH,"string mismatch");
            check(AnnotationMatcher.text(item,descriptor,1,"type",EncodedValue.TYPE,DexSourceExport.typeAt(set,1,8,1000),resolver,10,vl)==AnnotationMatcher.MATCH,"type resolution");
            check(AnnotationMatcher.text(item,descriptor,1,"str",EncodedValue.STRING,expected,null,10,vl)==AnnotationMatcher.UNKNOWN,"no resolver");
            check(AnnotationMatcher.text(item,descriptor,1,"str",EncodedValue.STRING,expected,(k,i)->null,10,vl)==AnnotationMatcher.UNKNOWN,"unavailable resolver");
            fails(IllegalStateException.class,()->AnnotationMatcher.text(item,descriptor,1,"str",EncodedValue.STRING,expected,(k,i)->{throw new IllegalStateException("resolver failure");},10,vl));
            fails(IllegalArgumentException.class,()->AnnotationMatcher.scalar(item,descriptor,1,"n",EncodedValue.INT,0,1,vl));
            fails(IllegalArgumentException.class,()->AnnotationMatcher.scalar(item,descriptor,1,"ints",EncodedValue.INT,0,10,new EncodedValue.Limits(1,100,20)));
            fails(IllegalArgumentException.class,()->AnnotationMatcher.scalar(item,descriptor,1,"ints",EncodedValue.ARRAY,0,10,vl));
            fails(EncodedValue.DecodeException.class,()->AnnotationMatcher.scalar(item,descriptor,1,"ints",EncodedValue.INT,0,10,new EncodedValue.Limits(1024,1,1)));
            check(item.element(0).encodedValueLength()==item.element(0).encodedValue().length,"pre-copy length");
        }
        check(AnnotationMatcher.scalar(held.item(0),descriptor,1,"n",EncodedValue.INT,-7,10,vl)==AnnotationMatcher.MATCH,"copied result after close");
        System.out.println("PASS exact static annotation scalar/text, source-local resolution, unknown/default, limits and copied lifetime");
    }
}
