package io.github.jichuo1.dexmeguviz;

import java.nio.file.Files;
import java.nio.file.Path;

/** Host JNI fixture only; no Android/ART, loader or reflection parity claim. */
public final class MethodParametersHostTest {
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static void status(int expected,Runnable body){try{body.run();throw new AssertionError("expected native status "+expected);}catch(NativeEngine.NativeFailure failure){check(failure.status==expected,"unexpected status "+failure.status);}}
    public static void main(String[] args)throws Exception{
        check(args.length==5,"fixture arguments");byte[] named=Files.readAllBytes(Path.of(args[0])),stripped=Files.readAllBytes(Path.of(args[1])),noindex=Files.readAllBytes(Path.of(args[2])),mismatch=Files.readAllBytes(Path.of(args[3])),resource=Files.readAllBytes(Path.of(args[4]));
        MethodParametersResult retained;
        try(NativeEngine.Snapshot snap=NativeEngine.openRawDex(named,"named")){
            retained=snap.inspectMethodParameters(2);check(retained.debugState==MethodParametersResult.DEBUG_PRESENT&&retained.methodRef==2&&retained.parameterCount()==2&&retained.returnType.equals("J")&&retained.slot.equals("named"),"named identity");
            var a=retained.parameter(0);var b=retained.parameter(1);check(a.nameState==MethodParametersResult.NAME_PRESENT&&"\u96ea".equals(a.name)&&a.typeDescriptor.equals("Ljava/lang/String;")&&b.nameState==MethodParametersResult.NAME_PRESENT&&b.name.equals("count")&&b.typeDescriptor.equals("J"),"UTF-16 name/type");
            var external=snap.inspectMethodParameters(5);check(external.debugState==MethodParametersResult.DEBUG_NO_DEFINITION&&external.methodOrdinal==0xffffffffL&&external.parameterCount()==1&&external.parameter(0).nameState==MethodParametersResult.NAME_UNKNOWN&&external.parameter(0).name==null&&external.parameter(0).typeDescriptor.equals("Ljava/lang/String;"),"external reference");
            var abstractMethod=snap.inspectMethodParameters(1);check(abstractMethod.debugState==MethodParametersResult.DEBUG_NO_BODY&&abstractMethod.parameter(0).nameState==MethodParametersResult.NAME_UNKNOWN,"no body");
            var noArgs=snap.inspectMethodParameters(4);check(noArgs.debugState==MethodParametersResult.DEBUG_PRESENT&&noArgs.parameterCount()==0,"zero parameters");
            status(4,()->snap.inspectMethodParameters(2,1,1048576,100000000L,0));
            try{snap.inspectMethodParameters(2,1,0,100000000L,0);throw new AssertionError("invalid text limit");}catch(IllegalArgumentException expected){}
        }
        check(retained.parameter(0).name.equals("\u96ea")&&retained.returnType.equals("J"),"copied result after close");
        try(NativeEngine.Snapshot snap=NativeEngine.openRawDex(stripped,"strip")){var v=snap.inspectMethodParameters(2);check(v.debugState==MethodParametersResult.DEBUG_NOT_PRESENT&&v.parameter(0).nameState==MethodParametersResult.NAME_UNKNOWN&&v.parameter(0).name==null,"stripped unknown");}
        try(NativeEngine.Snapshot snap=NativeEngine.openRawDex(noindex,"noindex")){var v=snap.inspectMethodParameters(0);check(v.debugState==MethodParametersResult.DEBUG_PRESENT&&v.parameter(0).nameState==MethodParametersResult.NAME_NO_INDEX&&v.parameter(0).name==null&&v.parameter(0).typeDescriptor.equals("D"),"encoded NO_INDEX");}
        try(NativeEngine.Snapshot snap=NativeEngine.openRawDex(mismatch,"bad")){status(2,()->snap.inspectMethodParameters(0));}
        try(NativeEngine.SourceSetSnapshot set=NativeEngine.openSources(new byte[][]{named,resource,stripped},new String[]{"base","resource","strip"},new int[]{NativeEngine.SOURCE_RAW_DEX,NativeEngine.SOURCE_APK,NativeEngine.SOURCE_RAW_DEX},new boolean[]{false,true,false})){
            var v=set.inspectMethodParameters(1,2);check(v.sourceIndex==1&&v.inputIndex==2&&v.slot.equals("strip")&&v.debugState==MethodParametersResult.DEBUG_NOT_PRESENT&&v.parameterCount()==2,"input versus occurrence");
        }
        System.out.println("PASS method parameter JNI named/unknown/no-index/external, source identity, budgets and copied lifetime");
    }
}
