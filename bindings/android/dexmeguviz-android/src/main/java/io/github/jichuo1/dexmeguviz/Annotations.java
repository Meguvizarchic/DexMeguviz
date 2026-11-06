package io.github.jichuo1.dexmeguviz;

/** Explicit static DEX annotations for a source-local type, field, method or parameter. */
public final class Annotations {
    private Annotations(){}
    public static final int CLASS=0,FIELD=1,METHOD=2,PARAMETER=3;
    public static final class Target {
        public final int kind;public final long referenceIndex,parameterIndex;
        private Target(int kind,long ref,long parameter){if(ref<0||ref>0xffffffffL||parameter<0||parameter>0xffffffffL)throw new IllegalArgumentException("target index outside uint32");this.kind=kind;referenceIndex=ref;parameterIndex=parameter;}
        public static Target classType(long typeIndex){return new Target(CLASS,typeIndex,0xffffffffL);}
        public static Target field(long fieldRef){return new Target(FIELD,fieldRef,0xffffffffL);}
        public static Target method(long methodRef){return new Target(METHOD,methodRef,0xffffffffL);}
        public static Target parameter(long methodRef,long parameterIndex){if(parameterIndex==0xffffffffL)throw new IllegalArgumentException("invalid parameter index");return new Target(PARAMETER,methodRef,parameterIndex);}
    }
    public static final class Limits {
        public final int maxRecords;public final long maxWork,maxEncodedBytes,deadlineAfterMs;
        public Limits(int maxRecords,long maxWork,long maxEncodedBytes,long deadlineAfterMs){if(maxRecords<1||maxRecords>100000||maxWork<1||maxWork>100000000L||maxEncodedBytes<1||maxEncodedBytes>(64L<<20)||deadlineAfterMs<0||deadlineAfterMs>86400000L)throw new IllegalArgumentException("invalid annotation limits");this.maxRecords=maxRecords;this.maxWork=maxWork;this.maxEncodedBytes=maxEncodedBytes;this.deadlineAfterMs=deadlineAfterMs;}
    }
    private static native byte[] nativeCollect(Object snapshot,boolean sourceSet,int sourceIndex,int kind,long targetRef,long parameterIndex,int maxRecords,long maxWork,long maxEncodedBytes,long deadlineAfterMs);
    private static AnnotationResult collect0(Object snapshot,boolean sourceSet,int sourceIndex,Target target,Limits limits){
        if(snapshot==null||target==null||limits==null)throw new NullPointerException("snapshot, target and limits are required");if(sourceIndex<0)throw new IllegalArgumentException("negative source index");
        synchronized(snapshot){return AnnotationResult.decode(nativeCollect(snapshot,sourceSet,sourceIndex,target.kind,target.referenceIndex,target.parameterIndex,limits.maxRecords,limits.maxWork,limits.maxEncodedBytes,limits.deadlineAfterMs));}
    }
    public static AnnotationResult collect(NativeEngine.Snapshot snapshot,Target target,Limits limits){return collect0(snapshot,false,0,target,limits);}
    public static AnnotationResult collect(NativeEngine.SourceSetSnapshot snapshot,int sourceIndex,Target target,Limits limits){return collect0(snapshot,true,sourceIndex,target,limits);}
}
