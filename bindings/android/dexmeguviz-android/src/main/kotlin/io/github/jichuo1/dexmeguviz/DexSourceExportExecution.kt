package io.github.jichuo1.dexmeguviz

/** Synchronous copy of a selected static DEX source; schedule away from the UI thread. */
public object DexSourceExportExecution {
    public fun prototypeAt(snapshot:NativeEngine.Snapshot,index:Long,maxUnits:Int):String = DexSourceExport.prototypeAt(snapshot,index,maxUnits)
    public fun prototypeAt(snapshot:NativeEngine.SourceSetSnapshot,sourceIndex:Int,index:Long,maxUnits:Int):String = DexSourceExport.prototypeAt(snapshot,sourceIndex,index,maxUnits)
    public fun fieldRefAt(snapshot:NativeEngine.Snapshot,index:Long):LongArray = DexSourceExport.fieldRefAt(snapshot,index)
    public fun methodRefAt(snapshot:NativeEngine.Snapshot,index:Long):LongArray = DexSourceExport.methodRefAt(snapshot,index)
    public fun fieldRefAt(snapshot:NativeEngine.SourceSetSnapshot,sourceIndex:Int,index:Long):LongArray = DexSourceExport.fieldRefAt(snapshot,sourceIndex,index)
    public fun methodRefAt(snapshot:NativeEngine.SourceSetSnapshot,sourceIndex:Int,index:Long):LongArray = DexSourceExport.methodRefAt(snapshot,sourceIndex,index)
    public fun stringAt(snapshot:NativeEngine.Snapshot,index:Long,maxUnits:Int):String = DexSourceExport.stringAt(snapshot,index,maxUnits)
    public fun typeAt(snapshot:NativeEngine.Snapshot,index:Long,maxUnits:Int):String = DexSourceExport.typeAt(snapshot,index,maxUnits)
    public fun stringAt(snapshot:NativeEngine.SourceSetSnapshot,sourceIndex:Int,index:Long,maxUnits:Int):String = DexSourceExport.stringAt(snapshot,sourceIndex,index,maxUnits)
    public fun typeAt(snapshot:NativeEngine.SourceSetSnapshot,sourceIndex:Int,index:Long,maxUnits:Int):String = DexSourceExport.typeAt(snapshot,sourceIndex,index,maxUnits)
    public fun copy(snapshot:NativeEngine.Snapshot,maxBytes:Long):ByteArray = DexSourceExport.copy(snapshot,maxBytes)
    public fun copy(snapshot:NativeEngine.SourceSetSnapshot,sourceIndex:Int,maxBytes:Long):ByteArray = DexSourceExport.copy(snapshot,sourceIndex,maxBytes)
}
