package io.github.jichuo1.dexmeguviz;

import java.util.Arrays;

/** A bounded, lossless structural interpretation of one DEX encoded_value.
 *  Reference and annotation name/type indexes remain source-local, unresolved indexes. */
public final class EncodedValue {
    public static final int BYTE=0x00, SHORT=0x02, CHAR=0x03, INT=0x04, LONG=0x06,
        FLOAT=0x10, DOUBLE=0x11, METHOD_TYPE=0x15, METHOD_HANDLE=0x16, STRING=0x17,
        TYPE=0x18, FIELD=0x19, METHOD=0x1a, ENUM=0x1b, ARRAY=0x1c,
        ANNOTATION=0x1d, NULL=0x1e, BOOLEAN=0x1f;

    /** Independent limits for this decode; they do not bound VM memory or wall time. */
    public static final class Limits {
        public final int maxBytes, maxNodes, maxDepth;
        public Limits(int maxBytes, int maxNodes, int maxDepth) {
            if (maxBytes < 1 || maxBytes > (8 << 20) || maxNodes < 1 || maxNodes > 100000 || maxDepth < 1 || maxDepth > 64)
                throw new IllegalArgumentException("invalid encoded value limits");
            this.maxBytes=maxBytes; this.maxNodes=maxNodes; this.maxDepth=maxDepth;
        }
    }

    /** Thrown when input is malformed, unsupported, or exceeds an explicit limit. */
    public static final class DecodeException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        private DecodeException(String message) { super(message); }
    }

    public static final class Element {
        public final long nameIndex;
        public final Value value;
        private Element(long nameIndex, Value value) { this.nameIndex=nameIndex; this.value=value; }
    }

    /** Immutable value. originalBytes() returns the exact encoding for this node. */
    public static final class Value {
        public final int kind, valueArg;
        private final byte[] input;
        private final int start, end;
        private final long bits;
        private final long annotationTypeIndex;
        private final Value[] children;
        private final Element[] elements;
        private Value(int kind, int arg, byte[] input, int start, int end, long bits,
                      long annotationTypeIndex, Value[] children, Element[] elements) {
            this.kind=kind; this.valueArg=arg; this.input=input; this.start=start; this.end=end;
            this.bits=bits; this.annotationTypeIndex=annotationTypeIndex;
            this.children=children; this.elements=elements;
        }
        public byte[] originalBytes() { return Arrays.copyOfRange(input,start,end); }
        /** Signed long for BYTE/SHORT/INT/LONG, unsigned numeric value for CHAR. */
        public long integerValue() {
            if (kind!=BYTE && kind!=SHORT && kind!=CHAR && kind!=INT && kind!=LONG) throw wrongKind();
            return bits;
        }
        /** IEEE 754 bits, zero-extended to long for FLOAT; DOUBLE retains all 64 bits. */
        public long floatingRawBits() { if (kind!=FLOAT && kind!=DOUBLE) throw wrongKind(); return bits; }
        /** An unsigned source-local index; not a resolved item or validation of its range. */
        public long referenceIndex() { if (kind<METHOD_TYPE || kind>ENUM) throw wrongKind(); return bits; }
        public boolean booleanValue() { if (kind!=BOOLEAN) throw wrongKind(); return bits != 0; }
        public int arraySize() { if (kind!=ARRAY) throw wrongKind(); return children.length; }
        public Value arrayValue(int index) { if (kind!=ARRAY) throw wrongKind(); return children[index]; }
        public long annotationTypeIndex() { if (kind!=ANNOTATION) throw wrongKind(); return annotationTypeIndex; }
        public int annotationSize() { if (kind!=ANNOTATION) throw wrongKind(); return elements.length; }
        public Element annotationElement(int index) { if (kind!=ANNOTATION) throw wrongKind(); return elements[index]; }
        private IllegalStateException wrongKind() { return new IllegalStateException("accessor does not match encoded value kind"); }
    }

    private EncodedValue() {}

    /** Decode exactly one value; malformed data, trailing bytes and exceeded limits fail. */
    public static Value decode(byte[] encoded, Limits limits) {
        if (encoded==null || limits==null) throw new NullPointerException("encoded and limits are required");
        if (encoded.length==0 || encoded.length>limits.maxBytes) throw new DecodeException("encoded byte limit or empty input");
        Parser parser=new Parser(encoded.clone(), limits);
        Value result=parser.value(1);
        if (parser.pos != parser.input.length) throw new DecodeException("trailing encoded bytes");
        return result;
    }

    private static final class Parser {
        final byte[] input;
        final Limits limits;
        int pos, nodes, pending;
        Parser(byte[] input, Limits limits) { this.input=input; this.limits=limits; }
        int u8() { if (pos>=input.length) throw new DecodeException("truncated encoded value"); return input[pos++]&255; }
        long uleb() {
            long v=0;
            for (int i=0;i<5;i++) {
                int b=u8();
                if (i==4 && (b&0xf0)!=0) throw new DecodeException("uleb128 overflow");
                v|=(long)(b&0x7f)<<(7*i);
                if ((b&0x80)==0) return v;
            }
            throw new DecodeException("invalid uleb128");
        }
        int count(long count, boolean names) {
            if (count>limits.maxNodes-nodes-pending || count>(input.length-pos)/(names?2:1))
                throw new DecodeException("child count exceeds limit or available bytes");
            pending+=(int)count;
            return (int)count;
        }
        long payload(int size) {
            if (size>input.length-pos) throw new DecodeException("truncated encoded payload");
            long v=0;
            for (int i=0;i<size;i++) v|=(long)u8()<<(8*i);
            return v;
        }
        Value value(int depth) {
            if(depth>1) --pending;
            if (depth>limits.maxDepth || ++nodes>limits.maxNodes) throw new DecodeException("value depth or node limit");
            int start=pos, header=u8(), kind=header&31, arg=header>>>5;
            long bits=0, annotationType=0;
            Value[] children=null;
            Element[] elements=null;
            int maxArg=-1;
            switch(kind) {
                case BYTE: maxArg=0; break;
                case SHORT: case CHAR: maxArg=1; break;
                case INT: case FLOAT: case METHOD_TYPE: case METHOD_HANDLE: case STRING: case TYPE: case FIELD: case METHOD: case ENUM: maxArg=3; break;
                case LONG: case DOUBLE: maxArg=7; break;
                case ARRAY: case ANNOTATION: case NULL:
                    if(arg!=0) throw new DecodeException("invalid value argument");
                    break;
                case BOOLEAN:
                    if(arg>1) throw new DecodeException("invalid boolean argument");
                    bits=arg; break;
                default: throw new DecodeException("unsupported value type");
            }
            if (maxArg>=0) {
                if (arg>maxArg) throw new DecodeException("invalid value argument");
                int size=arg+1;
                bits=payload(size);
                if(kind==BYTE || kind==SHORT || kind==INT || kind==LONG) {
                    int shift=64-size*8;
                    bits=(bits<<shift)>>shift;
                } else if(kind==FLOAT) bits=(bits<<(32-size*8))&0xffffffffL;
                else if(kind==DOUBLE) bits=bits<<(64-size*8);
            } else if (kind==ARRAY) {
                int count=count(uleb(),false);
                children=new Value[count];
                for(int i=0;i<count;i++) children[i]=value(depth+1);
            } else if (kind==ANNOTATION) {
                annotationType=uleb();
                int count=count(uleb(),true);
                elements=new Element[count];
                long previous=-1;
                for(int i=0;i<count;i++) {
                    long name=uleb();
                    if(name<=previous) throw new DecodeException("annotation names not strictly increasing");
                    previous=name;
                    elements[i]=new Element(name,value(depth+1));
                }
            }
            return new Value(kind,arg,input,start,pos,bits,annotationType,children,elements);
        }
    }
}
