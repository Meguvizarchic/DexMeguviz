package io.github.jichuo1.dexmeguviz;

/** Exact ordered matching of explicitly encoded DEX annotation scalar arrays. */
public final class AnnotationArrayMatcher {
    private AnnotationArrayMatcher() {}

    /** kinds and values are parallel arrays; references are source-local indices. */
    public static int exact(AnnotationResult.Item item,String descriptor,int visibility,String name,
                            int[] kinds,long[] values,int maxElements,EncodedValue.Limits limits) {
        return match(item,descriptor,visibility,name,kinds,values,maxElements,limits,0);
    }

    /** Ordered subsequence: duplicate conditions require distinct matching array positions. */
    public static int subsequence(AnnotationResult.Item item,String descriptor,int visibility,String name,
                                  int[] kinds,long[] values,int maxElements,EncodedValue.Limits limits) {
        return match(item,descriptor,visibility,name,kinds,values,maxElements,limits,1);
    }

    /** Unordered one-to-one scalar matching; equalCount also requires equal array lengths. */
    public static int unorderedScalars(AnnotationResult.Item item,String descriptor,int visibility,String name,
                                       int[] kinds,long[] values,boolean equalCount,int maxElements,EncodedValue.Limits limits) {
        return match(item,descriptor,visibility,name,kinds,values,maxElements,limits,equalCount?3:2);
    }

    private static int match(AnnotationResult.Item item,String descriptor,int visibility,String name,
                             int[] kinds,long[] values,int maxElements,EncodedValue.Limits limits,int mode) {
        if(name==null || kinds==null || values==null || limits==null)
            throw new NullPointerException("name, expected arrays and limits are required");
        if(name.isEmpty() || maxElements<1 || maxElements>100000 || kinds.length!=values.length)
            throw new IllegalArgumentException("invalid name, element limit or expected arrays");
        // Count the root ARRAY node before allocating copies of the expected arrays.
        if(kinds.length>limits.maxNodes-1) throw new IllegalArgumentException("expected array node limit exceeded");
        int[] expectedKinds=kinds.clone();long[] expectedValues=values.clone();
        for(int i=0;i<expectedKinds.length;i++) {
            validateExpected(expectedKinds[i],expectedValues[i]);
            if(mode>=2 && !primitiveKind(expectedKinds[i])) throw new IllegalArgumentException("unordered mode supports primitive values only");
        }
        if(AnnotationMatcher.metadata(item,descriptor,visibility)==AnnotationMatcher.NO_MATCH) return AnnotationMatcher.NO_MATCH;
        if(item.elementCount()>maxElements) throw new IllegalArgumentException("annotation element limit exceeded");
        AnnotationResult.Element element=null;
        for(int i=0;i<item.elementCount();i++) {
            var next=item.element(i);
            if(next.name.equals(name)) {
                if(element!=null) throw new IllegalStateException("duplicate annotation element name");
                element=next;
            }
        }
        if(element==null) return AnnotationMatcher.UNKNOWN;
        if(element.encodedValueLength()>limits.maxBytes) throw new IllegalArgumentException("annotation value byte limit exceeded");
        var value=EncodedValue.decode(element.encodedValue(),limits);
        if(value.kind!=EncodedValue.ARRAY) return AnnotationMatcher.NO_MATCH;
        int count=value.arraySize();
        // Reject unsupported nested values before using length or any mismatch as a result.
        for(int i=0;i<count;i++) {
            int kind=value.arrayValue(i).kind;
            if(kind==EncodedValue.ARRAY || kind==EncodedValue.ANNOTATION)
                throw new UnsupportedOperationException("nested arrays and annotations are unsupported");
        }
        if(mode>=2) {
            if(expectedKinds.length>count || (mode==3 && expectedKinds.length!=count)) return AnnotationMatcher.NO_MATCH;
            java.util.HashMap<Integer,java.util.HashMap<Long,Integer>> needed=new java.util.HashMap<>();
            for(int i=0;i<expectedKinds.length;i++) {
                int kind=expectedKinds[i];long valueBits=expectedValues[i];
                if(isNaN(kind,valueBits)) return AnnotationMatcher.NO_MATCH;
                valueBits=normalBits(kind,valueBits);
                var byValue=needed.computeIfAbsent(kind,k->new java.util.HashMap<>());
                byValue.put(valueBits,byValue.getOrDefault(valueBits,0)+1);
            }
            int remaining=expectedKinds.length;
            for(int i=0;i<count && remaining>0;i++) {
                var child=value.arrayValue(i);int kind=child.kind;
                if(!primitiveKind(kind)) continue;
                long valueBits=bits(child);if(isNaN(kind,valueBits))continue;
                var byValue=needed.get(kind);if(byValue==null)continue;
                valueBits=normalBits(kind,valueBits);Integer n=byValue.get(valueBits);
                if(n!=null && n>0) {byValue.put(valueBits,n-1);remaining--;}
            }
            return remaining==0 ? AnnotationMatcher.MATCH : AnnotationMatcher.NO_MATCH;
        }
        if(mode==1) {
            int expectedIndex=0;
            for(int i=0;i<count && expectedIndex<expectedKinds.length;i++) {
                var child=value.arrayValue(i);
                if(child.kind==expectedKinds[expectedIndex] && bits(child)==expectedValues[expectedIndex]) expectedIndex++;
            }
            return expectedIndex==expectedKinds.length ? AnnotationMatcher.MATCH : AnnotationMatcher.NO_MATCH;
        }
        if(count!=expectedKinds.length) return AnnotationMatcher.NO_MATCH;
        for(int i=0;i<count;i++) {
            var child=value.arrayValue(i);int kind=expectedKinds[i];
            if(child.kind!=kind || bits(child)!=expectedValues[i]) return AnnotationMatcher.NO_MATCH;
        }
        return AnnotationMatcher.MATCH;
    }
    private static void validateExpected(int kind,long value) {
        if(!scalarKind(kind)) throw new IllegalArgumentException("unsupported expected array value kind");
        if(kind>=EncodedValue.METHOD_TYPE && kind<=EncodedValue.ENUM && (value<0 || value>0xffffffffL))
            throw new IllegalArgumentException("reference index out of range");
        if(kind==EncodedValue.FLOAT && (value<0 || value>0xffffffffL)) throw new IllegalArgumentException("float bits out of range");
        if(kind==EncodedValue.BOOLEAN && value!=0 && value!=1 || kind==EncodedValue.NULL && value!=0)
            throw new IllegalArgumentException("invalid expected value");
    }
    private static boolean primitiveKind(int kind) {
        return kind==EncodedValue.BYTE || kind==EncodedValue.SHORT || kind==EncodedValue.CHAR || kind==EncodedValue.INT || kind==EncodedValue.LONG || kind==EncodedValue.FLOAT || kind==EncodedValue.DOUBLE || kind==EncodedValue.NULL || kind==EncodedValue.BOOLEAN;
    }
    private static boolean isNaN(int kind,long bits) {
        return kind==EncodedValue.FLOAT ? Float.isNaN(Float.intBitsToFloat((int)bits)) : kind==EncodedValue.DOUBLE && Double.isNaN(Double.longBitsToDouble(bits));
    }
    private static long normalBits(int kind,long bits) {
        if(kind==EncodedValue.FLOAT && (bits&0x7fffffffL)==0) return 0;
        if(kind==EncodedValue.DOUBLE && (bits&0x7fffffffffffffffL)==0) return 0;
        return bits;
    }
    private static boolean scalarKind(int kind) {
        return kind==EncodedValue.BYTE || kind==EncodedValue.SHORT || kind==EncodedValue.CHAR || kind==EncodedValue.INT || kind==EncodedValue.LONG || kind==EncodedValue.FLOAT || kind==EncodedValue.DOUBLE || kind>=EncodedValue.METHOD_TYPE && kind<=EncodedValue.ENUM || kind==EncodedValue.NULL || kind==EncodedValue.BOOLEAN;
    }
    private static long bits(EncodedValue.Value value) {
        int kind=value.kind;
        if(kind==EncodedValue.NULL) return 0;
        if(kind==EncodedValue.BOOLEAN) return value.booleanValue()?1:0;
        if(kind==EncodedValue.FLOAT || kind==EncodedValue.DOUBLE) return value.floatingRawBits();
        if(kind>=EncodedValue.METHOD_TYPE && kind<=EncodedValue.ENUM) return value.referenceIndex();
        return value.integerValue();
    }
}
