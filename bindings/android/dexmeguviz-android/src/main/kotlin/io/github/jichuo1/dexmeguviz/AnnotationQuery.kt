package io.github.jichuo1.dexmeguviz

/** Synchronous static DEX annotation inspection; schedule off the UI thread. */
public object AnnotationExecution {
    public fun inspect(snapshot:NativeEngine.Snapshot,target:Annotations.Target,limits:Annotations.Limits):AnnotationResult = Annotations.collect(snapshot,target,limits)
    public fun inspect(snapshot:NativeEngine.SourceSetSnapshot,sourceIndex:Int,target:Annotations.Target,limits:Annotations.Limits):AnnotationResult = Annotations.collect(snapshot,sourceIndex,target,limits)
}
