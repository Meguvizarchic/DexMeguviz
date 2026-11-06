package io.github.jichuo1.dexmeguviz
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path

fun main(args:Array<String>){
 check(args.size==2);val root=Path.of(args[0]);val saved=Path.of(args[1]);
 fun run(names:List<String>,expected:CallerFieldRelationResult.Status,reason:Long,nodes:Int,edges:Int,checks:Int=0,wire:Boolean=false){
  val bytes=names.map{Files.readAllBytes(root.resolve(it))}.toTypedArray();val slots=names.indices.map{"s$it"}.toTypedArray();val snapshot=NativeEngine.openRawDexSet(bytes,slots)
  try{
   val field=FieldDeclarationQuery(slots.toList(),FieldDeclarationScope.ANY,maxResults=100)
   val ordinary=FieldDeclarationCallerQuery(field,join=UseSymbolJoin.JOIN)
   val query=CallerFieldRelationQuery(ordinary);val raw=query.toQueryIrJson().toByteArray(Charsets.UTF_8)
   val old=TypedFieldDeclarationCallerExecution.execute(snapshot,ordinary);val observed=CallerFieldRelationExecution.execute(snapshot,query)
   check(observed.graph.rowCount()==2&&observed.rowCount()==2&&observed.graph.unknownRows==old.unknownRows&&observed.graph.decision==old.decision)
   for(i in 0 until observed.rowCount()){val r=observed.relation(i);check(r.status==expected&&r.reason==reason&&r.nodeCount()==nodes&&r.edgeCount()==edges&&r.interfaceObjectCheckCount()==checks)}
   try{snapshot.queryFieldDeclarationGraph(raw);error("old v19 JNI accepted observation")}catch(e:NativeEngine.NativeFailure){check(e.status==3)}
   if(wire){
    Files.write(saved,raw);val token=NativeEngine.SourceSetSnapshot::class.java.getDeclaredField("token");token.isAccessible=true
    val method=NativeEngine::class.java.getDeclaredMethod("nativeQueryCallerFieldRelationGraph",java.lang.Long.TYPE,ByteArray::class.java,java.lang.Boolean.TYPE);method.isAccessible=true
    @Suppress("UNCHECKED_CAST") val parts=method.invoke(null,token.getLong(snapshot),raw,true) as Array<ByteArray>
    check(CallerFieldRelationResult.decode(parts).rowCount()==2)
    fun reject(mut:(ByteBuffer)->Unit){val bad=arrayOf(parts[0].clone(),parts[1].clone());mut(ByteBuffer.wrap(bad[1]).order(ByteOrder.LITTLE_ENDIAN));try{CallerFieldRelationResult.decode(bad);error("forged annotation accepted")}catch(_:IllegalStateException){}}
    // Header starts after magic,row-count,record-count; reject a forged event PC/target.
    reject{it.putInt(12+16*4,12345)};reject{it.putInt(12+11*4,77)}
    // First row is EXTERNAL: first record after header is a node. Corrupt root source.
    reject{it.putInt(12+17*4+5*4,77)}
    if(checks>0){val objectRecord=12+(1+nodes+edges)*17*4;reject{it.putInt(objectRecord+7*4,99)}}
    try{CallerFieldRelationResult.decode(arrayOf(parts[0],parts[1].copyOf(parts[1].size-1)));error("truncation accepted")}catch(_:IllegalStateException){}
   }
  }finally{snapshot.close()}
 }
 run(listOf("child-self.dex","parent-target.dex","object.dex"),CallerFieldRelationResult.Status.SELF,0,1,0)
 run(listOf("child-ancestor.dex","parent-target.dex","object.dex"),CallerFieldRelationResult.Status.ANCESTOR,0,2,0)
 run(listOf("child-hide.dex","parent-target.dex","object.dex"),CallerFieldRelationResult.Status.ANCESTOR,0,2,0)
 run(listOf("caller-external.dex","child-target.dex","parent-target.dex","object.dex"),CallerFieldRelationResult.Status.EXTERNAL,0,2,1,wire=true)
 run(listOf("caller-missing.dex","child-target.dex","parent-target.dex"),CallerFieldRelationResult.Status.UNKNOWN,1,0,0)
 run(listOf("caller-cycle-a.dex","caller-cycle-b.dex","child-target.dex","parent-target.dex"),CallerFieldRelationResult.Status.UNKNOWN,3,0,0)
 run(listOf("caller-interface.dex","interface-a.dex","interface-common.dex","object.dex"),CallerFieldRelationResult.Status.ANCESTOR,0,3,0)
 run(listOf("caller-diamond-target.dex","interface-a.dex","interface-b.dex","interface-common.dex","object.dex"),CallerFieldRelationResult.Status.ANCESTOR,0,3,0)
 run(listOf("caller-diamond.dex","child-target.dex","parent-target.dex","object.dex","interface-a.dex","interface-b.dex","interface-common.dex"),CallerFieldRelationResult.Status.EXTERNAL,0,5,5,3)
 run(listOf("interface-caller.dex","child-target.dex","parent-target.dex"),CallerFieldRelationResult.Status.UNKNOWN,1,0,0)
 run(listOf("interface-caller.dex","child-target.dex","parent-target.dex","object.dex"),CallerFieldRelationResult.Status.EXTERNAL,0,1,0,1,wire=true)
 run(listOf("interface-caller.dex","child-target.dex","parent-target.dex","object.dex","object.dex"),CallerFieldRelationResult.Status.UNKNOWN,2,0,0)
 run(listOf("interface-caller.dex","child-target.dex","parent-target.dex","object-invalid.dex"),CallerFieldRelationResult.Status.UNKNOWN,4,0,0)
 println("PASS Kotlin caller class relation, old entry rejection and corrupt separate wire")
}
