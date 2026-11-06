package io.github.jichuo1.dexmeguviz;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Copied checked facts for one selected local DEX method. No runtime binding,
 * ART verification, cross-source resolution, or inferred numeric type is implied. */
public final class MethodFactsResult {
    public enum Category {
        STRINGS(1), FIELDS(2), NUMBERS(4), INVOKES(8), TYPES(16), INSTRUCTIONS(32);
        public final int mask; Category(int mask){this.mask=mask;}
    }
    public enum Availability { NOT_REQUESTED, NO_BODY, CHECKED }
    public final long sourceIndex,inputIndex,methodOrdinal,methodRef,codeOffset,codeUnits,validationWork;
    public final long callerFlags,callerDeclarationOffset,archiveEntryIndex,sourceBytes;
    public final int requestedMask;
    public final boolean hasBody,instructionChecked,crcVerified,headerConsistencyVerified,expectedDigestVerified;
    public final String snapshotId,slot,role,sourceSha256,contentId,occurrenceId,logicalDexId,archiveSha256,archiveEntryName;
    public final String callerOwner,callerName,callerPrototype;
    private final StringUse[] strings;private final FieldUse[] fields;private final NumberUse[] numbers;
    private final Invoke[] invokes;private final TypeUse[] types;private final Instruction[] instructions;

    private MethodFactsResult(Reader r){
        if(r.i()!=0x46474d44)throw new IllegalStateException("unknown method facts wire");
        sourceIndex=r.u();inputIndex=r.u();methodOrdinal=r.u();methodRef=r.u();codeOffset=r.u();hasBody=r.bool();instructionChecked=r.bool();codeUnits=r.u();requestedMask=r.i();
        int ns=r.count(),nf=r.count(),nn=r.count(),ni=r.count(),nt=r.count(),nx=r.count();long total=(long)ns+nf+nn+ni+nt+nx;validationWork=r.l();
        snapshotId=r.ascii();slot=r.ascii();role=r.ascii();sourceSha256=r.ascii();contentId=r.ascii();occurrenceId=r.ascii();logicalDexId=r.ascii();archiveSha256=r.ascii();archiveEntryName=r.ascii();archiveEntryIndex=r.u();sourceBytes=r.l();crcVerified=r.bool();headerConsistencyVerified=r.bool();expectedDigestVerified=r.bool();
        callerFlags=r.u();callerDeclarationOffset=r.u();callerOwner=r.text();callerName=r.text();callerPrototype=r.text();
        if(sourceIndex>=64||inputIndex>=8||snapshotId==null||slot==null||role==null||sourceSha256==null||contentId==null||occurrenceId==null||logicalDexId==null||callerOwner==null||callerName==null||callerPrototype==null||requestedMask<=0||(requestedMask&~63)!=0||total>100000||hasBody!=(codeOffset!=0)||instructionChecked!=hasBody||(!hasBody&&(total!=0||codeUnits!=0||validationWork!=0))||(!requested(Category.STRINGS)&&ns!=0)||(!requested(Category.FIELDS)&&nf!=0)||(!requested(Category.NUMBERS)&&nn!=0)||(!requested(Category.INVOKES)&&ni!=0)||(!requested(Category.TYPES)&&nt!=0)||(!requested(Category.INSTRUCTIONS)&&nx!=0))throw new IllegalStateException("invalid method facts identity or counts");
        strings=new StringUse[ns];for(int i=0;i<ns;i++)strings[i]=new StringUse(r,codeUnits);
        fields=new FieldUse[nf];for(int i=0;i<nf;i++)fields[i]=new FieldUse(r,codeUnits);
        numbers=new NumberUse[nn];for(int i=0;i<nn;i++)numbers[i]=new NumberUse(r,codeUnits);
        invokes=new Invoke[ni];for(int i=0;i<ni;i++)invokes[i]=new Invoke(r,codeUnits);
        types=new TypeUse[nt];for(int i=0;i<nt;i++)types[i]=new TypeUse(r,codeUnits);
        instructions=new Instruction[nx];for(int i=0;i<nx;i++)instructions[i]=new Instruction(r,codeUnits);
        if(r.data.hasRemaining())throw new IllegalStateException("trailing method facts bytes");
    }
    static MethodFactsResult decode(byte[] bytes){if(bytes==null)throw new NullPointerException("method facts bytes");try{return new MethodFactsResult(new Reader(bytes));}catch(java.nio.BufferUnderflowException e){throw new IllegalStateException("truncated method facts wire",e);}}
    public boolean requested(Category category){if(category==null)throw new NullPointerException("category");return (requestedMask&category.mask)!=0;}
    public Availability availability(Category category){return !requested(category)?Availability.NOT_REQUESTED:!hasBody?Availability.NO_BODY:Availability.CHECKED;}
    private void require(Category c){if(!requested(c))throw new UnsupportedOperationException("method facts category not requested: "+c);}
    public int stringCount(){require(Category.STRINGS);return strings.length;}public StringUse string(int i){require(Category.STRINGS);return strings[i];}
    public int fieldCount(){require(Category.FIELDS);return fields.length;}public FieldUse field(int i){require(Category.FIELDS);return fields[i];}
    public int numberCount(){require(Category.NUMBERS);return numbers.length;}public NumberUse number(int i){require(Category.NUMBERS);return numbers[i];}
    public int invokeCount(){require(Category.INVOKES);return invokes.length;}public Invoke invoke(int i){require(Category.INVOKES);return invokes[i];}
    public int typeCount(){require(Category.TYPES);return types.length;}public TypeUse type(int i){require(Category.TYPES);return types[i];}
    public int instructionCount(){require(Category.INSTRUCTIONS);return instructions.length;}public Instruction instruction(int i){require(Category.INSTRUCTIONS);return instructions[i];}

    /** UTF-16 code units are retained, including NUL and unpaired surrogates. */
    public static final class StringUse {
        public final long dexPc,opcode,stringIndex;public final String value;
        private StringUse(Reader r,long units){dexPc=r.pc(units);opcode=r.opcode();stringIndex=r.u();value=r.text();if(value==null)throw new IllegalStateException("missing string value");}
    }
    public static final class FieldUse {
        public final long dexPc,opcode,fieldIndex;public final String owner,name,typeDescriptor;
        private FieldUse(Reader r,long units){dexPc=r.pc(units);opcode=r.opcode();fieldIndex=r.u();owner=r.text();name=r.text();typeDescriptor=r.text();if(owner==null||name==null||typeDescriptor==null)throw new IllegalStateException("missing field identity");}
    }
    public static final class NumberUse {
        public final long dexPc,opcode,bits;public final int widthBits,kind;
        /** bits is the exact encoded bit pattern; negative long values are valid for 64-bit literals. */
        private NumberUse(Reader r,long units){dexPc=r.pc(units);opcode=r.opcode();widthBits=r.i();kind=r.i();bits=r.bits();if((widthBits!=32&&widthBits!=64)||kind<0||kind>1||(widthBits==32&&(bits>>>32)!=0))throw new IllegalStateException("invalid numeric fact");}
    }
    public static final class Invoke {
        public final long dexPc,opcode,targetDomain,targetIndex,extraProto;public final String owner,name,prototype,extraPrototype;
        private Invoke(Reader r,long units){dexPc=r.pc(units);opcode=r.opcode();targetDomain=r.u();targetIndex=r.u();extraProto=r.u();owner=r.text();name=r.text();prototype=r.text();extraPrototype=r.text();
            if(targetDomain==2){if(!((opcode>=0x6e&&opcode<=0x72)||(opcode>=0x74&&opcode<=0x78))||extraProto!=0xffffffffL||owner==null||name==null||prototype==null||extraPrototype!=null)throw new IllegalStateException("ordinary invoke");}
            else if(targetDomain==3){if((opcode!=0xfa&&opcode!=0xfb)||extraProto==0xffffffffL||owner==null||name==null||prototype==null||extraPrototype==null)throw new IllegalStateException("polymorphic invoke");}
            else if(targetDomain==4){if((opcode!=0xfc&&opcode!=0xfd)||extraProto!=0xffffffffL||owner!=null||name!=null||prototype!=null||extraPrototype!=null)throw new IllegalStateException("custom invoke");}
            else throw new IllegalStateException("unknown invoke domain");}
    }
    public static final class TypeUse {
        public final long dexPc,opcode,typeIndex;public final String descriptor;
        private TypeUse(Reader r,long units){dexPc=r.pc(units);opcode=r.opcode();typeIndex=r.u();descriptor=r.text();if(descriptor==null||descriptor.isEmpty())throw new IllegalStateException("missing type descriptor");}
    }
    public static final class Instruction {
        public final long dexPc,width,opcode,payloadKind;
        private Instruction(Reader r,long units){dexPc=r.pc(units);width=r.u();opcode=r.opcode();payloadKind=r.u();if(width==0||width>units-dexPc||payloadKind>3)throw new IllegalStateException("invalid instruction range");}
    }
    private static final class Reader {
        final ByteBuffer data;
        Reader(byte[] b){if(b.length>8*1024*1024)throw new IllegalStateException("method facts wire limit");data=ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);}
        int i(){return data.getInt();}long u(){return Integer.toUnsignedLong(i());}long l(){long n=data.getLong();if(n<0)throw new IllegalStateException("counter overflow");return n;}long bits(){return data.getLong();}
        long pc(long units){long n=u();if(n>=units)throw new IllegalStateException("PC outside method body");return n;}long opcode(){long n=u();if(n>255)throw new IllegalStateException("opcode range");return n;}
        boolean bool(){int n=i();if(n!=0&&n!=1)throw new IllegalStateException("boolean");return n!=0;}
        int count(){int n=i();if(n<0||n>100000||n>data.remaining())throw new IllegalStateException("count");return n;}
        String ascii(){int n=i();if(n==-1)return null;if(n<0||n>1024||n>data.remaining())throw new IllegalStateException("identity");byte[] b=new byte[n];data.get(b);for(byte x:b)if(x<0)throw new IllegalStateException("identity");return new String(b,StandardCharsets.US_ASCII);}
        String text(){int n=i();if(n==-1)return null;if(n<0||n>1048576||n>data.remaining()/2)throw new IllegalStateException("text");char[] c=new char[n];for(int i=0;i<n;i++)c[i]=data.getChar();return new String(c);}
    }
}
