package io.github.jichuo1.dexmeguviz;

/** Exact, source-local matching of already copied static DEX annotations. */
public final class AnnotationMatcher {
    public static final int NO_MATCH=0, MATCH=1, UNKNOWN=2;

    /** Resolve a STRING or TYPE index in the same source as the AnnotationResult.
     * Return null if unavailable; exceptions propagate to the caller. */
    public interface Resolver { String resolve(int kind, long sourceLocalIndex); }

    private AnnotationMatcher() {}

    /** Exact descriptor and visibility; pass -1 for any of the three visibilities. */
    public static int metadata(AnnotationResult.Item item, String descriptor, int visibility) {
        if (item==null || descriptor==null) throw new NullPointerException("item and descriptor are required");
        if (descriptor.isEmpty() || visibility < -1 || visibility > 2)
            throw new IllegalArgumentException("invalid descriptor or visibility");
        return item.descriptor.equals(descriptor) && (visibility == -1 || item.visibility == visibility) ? MATCH : NO_MATCH;
    }

    /** Compare a scalar or a source-local reference index with exact kind and bits.
     * Missing explicit elements return UNKNOWN, because a declared default may apply. */
    public static int scalar(AnnotationResult.Item item, String descriptor, int visibility,
                             String name, int kind, long expected, int maxElements,
                             EncodedValue.Limits limits) {
        checkArguments(name, maxElements, limits);
        if (!scalarKind(kind)) throw new IllegalArgumentException("unsupported scalar kind");
        if (kind>=EncodedValue.METHOD_TYPE && kind<=EncodedValue.ENUM && (expected<0 || expected>0xffffffffL))
            throw new IllegalArgumentException("reference index out of range");
        if (kind==EncodedValue.FLOAT && (expected<0 || expected>0xffffffffL))
            throw new IllegalArgumentException("float bits out of range");
        if (kind==EncodedValue.BOOLEAN && expected!=0 && expected!=1 || kind==EncodedValue.NULL && expected!=0)
            throw new IllegalArgumentException("invalid expected value");
        if (metadata(item,descriptor,visibility)==NO_MATCH) return NO_MATCH;
        AnnotationResult.Element element=find(item,name,maxElements);
        if (element==null) return UNKNOWN;
        EncodedValue.Value value=decode(element,limits);
        if (value.kind!=kind) return NO_MATCH;
        long actual;
        if (kind==EncodedValue.NULL) actual=0;
        else if (kind==EncodedValue.BOOLEAN) actual=value.booleanValue()?1:0;
        else if (kind==EncodedValue.FLOAT || kind==EncodedValue.DOUBLE) actual=value.floatingRawBits();
        else if (kind>=EncodedValue.METHOD_TYPE && kind<=EncodedValue.ENUM) actual=value.referenceIndex();
        else actual=value.integerValue();
        return actual==expected ? MATCH : NO_MATCH;
    }

    /** Resolve and compare a STRING or TYPE value; unavailable resolution is UNKNOWN. */
    public static int text(AnnotationResult.Item item, String descriptor, int visibility,
                           String name, int kind, String expected, Resolver resolver,
                           int maxElements, EncodedValue.Limits limits) {
        checkArguments(name,maxElements,limits);
        if (expected==null) throw new NullPointerException("expected text is required");
        if (kind!=EncodedValue.STRING && kind!=EncodedValue.TYPE) throw new IllegalArgumentException("text requires STRING or TYPE");
        if (metadata(item,descriptor,visibility)==NO_MATCH) return NO_MATCH;
        AnnotationResult.Element element=find(item,name,maxElements);
        if (element==null) return UNKNOWN;
        EncodedValue.Value value=decode(element,limits);
        if (value.kind!=kind) return NO_MATCH;
        if (resolver==null) return UNKNOWN;
        String actual=resolver.resolve(kind,value.referenceIndex());
        return actual==null ? UNKNOWN : actual.equals(expected) ? MATCH : NO_MATCH;
    }

    private static void checkArguments(String name,int maxElements,EncodedValue.Limits limits) {
        if (name==null || limits==null) throw new NullPointerException("name and limits are required");
        if (name.isEmpty() || maxElements<1 || maxElements>100000) throw new IllegalArgumentException("invalid element name or limit");
    }
    private static AnnotationResult.Element find(AnnotationResult.Item item,String name,int maxElements) {
        if (item.elementCount()>maxElements) throw new IllegalArgumentException("annotation element limit exceeded");
        AnnotationResult.Element found=null;
        for(int i=0;i<item.elementCount();i++) {
            AnnotationResult.Element element=item.element(i);
            if(element.name.equals(name)) {
                if(found!=null) throw new IllegalStateException("duplicate annotation element name");
                found=element;
            }
        }
        return found;
    }
    private static EncodedValue.Value decode(AnnotationResult.Element element,EncodedValue.Limits limits) {
        if(element.encodedValueLength()>limits.maxBytes) throw new IllegalArgumentException("annotation value byte limit exceeded");
        return EncodedValue.decode(element.encodedValue(),limits);
    }
    private static boolean scalarKind(int kind) {
        return kind==EncodedValue.BYTE || kind==EncodedValue.SHORT || kind==EncodedValue.CHAR || kind==EncodedValue.INT || kind==EncodedValue.LONG || kind==EncodedValue.FLOAT || kind==EncodedValue.DOUBLE || kind>=EncodedValue.METHOD_TYPE && kind<=EncodedValue.ENUM || kind==EncodedValue.NULL || kind==EncodedValue.BOOLEAN;
    }
}
