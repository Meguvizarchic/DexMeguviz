package io.github.jichuo1.dexmeguviz

/** Bounds for copied static prototype/debug-name facts, not an RSS guarantee. */
public class MethodParametersLimits(
    public val maxParameters:Int=4096,public val maxTextUnits:Int=1048576,
    public val maxWork:Long=100000000L,public val deadlineAfterMs:Long=0L
){init{require(maxParameters in 1..65536&&maxTextUnits in 1..1048576&&maxWork in 1L..100000000L&&deadlineAfterMs in 0L..86400000L){"invalid method parameter limits"}}}

/** Same-source static metadata; this does not resolve members in a ClassLoader. */
public object MethodParametersExecution {
    public fun execute(snapshot:NativeEngine.Snapshot,methodRef:Long,limits:MethodParametersLimits=MethodParametersLimits()):MethodParametersResult =
        snapshot.inspectMethodParameters(methodRef,limits.maxParameters,limits.maxTextUnits,limits.maxWork,limits.deadlineAfterMs)
    public fun execute(snapshot:NativeEngine.SourceSetSnapshot,sourceIndex:Int,methodRef:Long,limits:MethodParametersLimits=MethodParametersLimits()):MethodParametersResult =
        snapshot.inspectMethodParameters(sourceIndex,methodRef,limits.maxParameters,limits.maxTextUnits,limits.maxWork,limits.deadlineAfterMs)
}
