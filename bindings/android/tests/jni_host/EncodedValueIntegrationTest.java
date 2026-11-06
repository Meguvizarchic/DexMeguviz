import io.github.jichuo1.dexmeguviz.AnnotationResult;
import io.github.jichuo1.dexmeguviz.Annotations;
import io.github.jichuo1.dexmeguviz.EncodedValue;
import io.github.jichuo1.dexmeguviz.NativeEngine;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class EncodedValueIntegrationTest {
    public static void main(String[] args) throws Exception {
        byte[] dex=Files.readAllBytes(Path.of(args[0]));
        AnnotationResult result;
        try(NativeEngine.Snapshot snapshot=NativeEngine.openRawDex(dex,"encoded-test")) {
            result=Annotations.collect(snapshot,Annotations.Target.classType(2),new Annotations.Limits(256,1000000,100000,10000));
        }
        int count=0, arrays=0, annotations=0;
        for(int i=0;i<result.itemCount();i++) {
            AnnotationResult.Item item=result.item(i);
            for(int j=0;j<item.elementCount();j++) {
                AnnotationResult.Element element=item.element(j);
                byte[] raw=element.encodedValue();
                EncodedValue.Value value=EncodedValue.decode(raw,new EncodedValue.Limits(1024*1024,10000,64));
                if(value.kind!=element.valueKind || value.valueArg!=element.valueArg || !Arrays.equals(value.originalBytes(),raw))
                    throw new AssertionError("mismatch with copied JNI annotation");
                count++;
                if(value.kind==EncodedValue.ARRAY) arrays++;
                if(value.kind==EncodedValue.ANNOTATION) annotations++;
            }
        }
        if(count==0 || arrays==0 || annotations==0) throw new AssertionError("fixture missing expected values");
        System.out.println("PASS real fixture after snapshot close: values="+count+", arrays="+arrays+", annotations="+annotations);
    }
}
