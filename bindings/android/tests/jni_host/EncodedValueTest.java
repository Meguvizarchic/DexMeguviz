import io.github.jichuo1.dexmeguviz.EncodedValue;
import java.util.Arrays;

public final class EncodedValueTest {
    private static int checks;
    private static final EncodedValue.Limits LIMITS=new EncodedValue.Limits(1024,100,16);
    private static byte[] b(int... x) { byte[] y=new byte[x.length]; for(int i=0;i<x.length;i++)y[i]=(byte)x[i]; return y; }
    private static EncodedValue.Value d(int... x) { return EncodedValue.decode(b(x),LIMITS); }
    private static void check(boolean b) { checks++; if(!b) throw new AssertionError("check "+checks); }
    private static void rejects(byte[] b, EncodedValue.Limits l) { boolean threw=false;try{EncodedValue.decode(b,l);}catch(EncodedValue.DecodeException e){threw=true;}check(threw); }
    public static void main(String[] args) {
        check(d(0x00,0x80).integerValue()==-128);
        check(d(0x22,0x00,0x80).integerValue()==-32768);
        check(d(0x23,0xff,0xff).integerValue()==65535);
        check(d(0x64,0,0,0,0x80).integerValue()==Integer.MIN_VALUE);
        check(d(0xe6,0,0,0,0,0,0,0,0x80).integerValue()==Long.MIN_VALUE);
        check(d(0x30,0x80,0x3f).floatingRawBits()==0x3f800000L);
        check(d(0x31,0xf0,0x3f).floatingRawBits()==0x3ff0000000000000L);
        check(d(0x71,0x42,0,0xf8,0x7f).floatingRawBits()==0x7ff8004200000000L);
        for(int kind=0x15;kind<=0x1b;kind++) check(d(kind|0x60,0xff,0xff,0xff,0xff).referenceIndex()==0xffffffffL);
        check(!d(0x1f).booleanValue()); check(d(0x3f).booleanValue()); check(d(0x1e).kind==EncodedValue.NULL);
        EncodedValue.Value nested=d(0x1c,2,0x1e,0x1d,3,2,1,0x00,0xff,5,0x1c,1,0x3f);
        check(nested.arraySize()==2 && nested.arrayValue(0).kind==EncodedValue.NULL);
        EncodedValue.Value ann=nested.arrayValue(1);
        check(ann.annotationTypeIndex()==3 && ann.annotationSize()==2);
        check(ann.annotationElement(0).nameIndex==1 && ann.annotationElement(0).value.integerValue()==-1);
        check(ann.annotationElement(1).nameIndex==5 && ann.annotationElement(1).value.arrayValue(0).booleanValue());
        byte[] original=ann.originalBytes(); original[0]=0;
        check(ann.originalBytes()[0]==0x1d);
        byte[] mutable=b(0x00,42); EncodedValue.Value imm=EncodedValue.decode(mutable,LIMITS);mutable[1]=0;
        check(imm.integerValue()==42 && Arrays.equals(imm.originalBytes(),b(0x00,42)));
        rejects(b(0x20,0),LIMITS); rejects(b(0x5f),LIMITS); rejects(b(0x0a),LIMITS);
        rejects(b(0x1c,0x80,0x80,0x80,0x80,0x10),LIMITS);
        rejects(b(0x1d,0,2,3,0x1e,3,0x1e),LIMITS);
        rejects(b(0x64,1,2),LIMITS); rejects(b(0x1e,0),LIMITS);
        rejects(b(0x1c,1,0x1e),new EncodedValue.Limits(100,1,16));
        rejects(b(0x1c,1,0x1e),new EncodedValue.Limits(100,10,1));
        rejects(b(0x1e,0),new EncodedValue.Limits(1,10,10));
        System.out.println("PASS "+checks+" checks");
    }
}
