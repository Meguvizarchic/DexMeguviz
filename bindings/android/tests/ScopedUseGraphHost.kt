package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

private fun nativeFailure(status: Int, action: () -> Unit) {
 try { action(); error("expected NativeFailure $status") } catch (e: NativeEngine.NativeFailure) { check(e.status==status) { "status ${e.status} expected $status" } }
}
private fun zip(vararg files: Pair<String,ByteArray>): ByteArray {
 val out=ByteArrayOutputStream();ZipOutputStream(out).use { z -> for ((name,bytes) in files) { z.putNextEntry(ZipEntry(name));z.write(bytes);z.closeEntry() } };return out.toByteArray()
}
private fun scope(json:String, slots:String) = json.replace("\"schema_version\":1,", "\"schema_version\":1,\"scope\":{\"slots\":$slots},")
fun main(args:Array<String>) {
 check(args.size==4);val bytes=Files.readAllBytes(Path.of(args[0]));val unknownBytes=Files.readAllBytes(Path.of(args[1]));val malformedCode=Files.readAllBytes(Path.of(args[2]));val out=Path.of(args[3]);val slot0="input:0:a.dex";val slot1="input:1:a.dex"
 val set=NativeEngine.openRawDexSet(arrayOf(bytes,bytes),arrayOf(slot0,slot1));check(!set.info().sourceScopeComplete)
 val a=ScopedInvokeSiteQuery(listOf(slot0),maxResults=100).toQueryIrJson()
 val b=ScopedInvokeSiteQuery(listOf(slot1),maxResults=100).toQueryIrJson()
 val empty=ScopedInvokeSiteQuery(emptyList(),intent=QueryIntent.EXISTS,maxResults=100).toQueryIrJson()
 val both=ScopedInvokeSiteQuery(listOf(slot0,slot1),maxResults=100).toQueryIrJson()
 val filtered=ScopedInvokeSiteQuery(listOf(slot0),UseEventPredicate.targetDomain(UseEventTargetDomain.CALL_SITE),QueryIntent.EXISTS,100).toQueryIrJson()
 val limited=ScopedInvokeSiteQuery(listOf(slot0),maxResults=1).toQueryIrJson()
 val nodeScope="{\"schema_version\":1,\"scope\":{\"slots\":[\"$slot0\"]},\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\",\"scope\":{\"slots\":[\"$slot1\"]}},\"intent\":\"exists\",\"max_results\":100}"
 val join=scope(UseTargetReferenceQuery(UseReferenceTarget.METHOD_REFERENCE,join=UseSymbolJoin.JOIN,maxResults=100).toQueryIrJson(),"[\"$slot0\"]")
 val semi=scope(UseTargetReferenceQuery(UseReferenceTarget.METHOD_REFERENCE,join=UseSymbolJoin.SEMI_JOIN,maxResults=100).toQueryIrJson(),"[\"$slot0\"]")
 val queries=listOf("a" to a,"b" to b,"empty" to empty,"both" to both,"filtered" to filtered,"limit" to limited,"intersection" to nodeScope,"join" to join,"semi" to semi)
 var held:UseGraphResult?=null
 fun show(name:String,r:UseGraphResult) {
  println("CASE $name ${r.queryId} ${r.snapshotId} ${r.executionStatus} ${r.coverage} ${r.decision} ${r.reason} ${r.rowCount()} ${r.unknownRows} ${if(r.profile.scopeComplete) 1 else 0} ${r.scopeSourceCount()}")
  repeat(r.scopeSourceCount()){ println("SCOPE $name ${r.scopeSource(it)}") }
  repeat(r.rowCount()) { i -> val row=r.row(i);val v=row.value;check(v.kind==1);val x=v.use
   println("ROW $name $i ${x.relation} ${x.sourceIndex} ${x.callerOrdinal} ${x.callerMethodRef} ${x.dexPc} ${x.opcode} ${x.codeOffset} ${x.targetDomain} ${x.targetIndex} ${x.extraProto}")
   repeat(row.linkCount()){ j -> val l=row.link(j);println("LINK $name $i $j ${l.nodeId} ${l.key} ${l.left.relation} ${l.left.sourceIndex} ${l.left.localIndex} ${l.left.dexPc} ${l.right.relation} ${l.right.sourceIndex} ${l.right.localIndex} ${l.right.dexPc}") }
   fun emit(tag:String,j:Int,z:UseGraphResult.Binding) { val w=z.value;val path=z.path().joinToString(""){if(it.toInt()==0) "L" else "R"}.ifEmpty{"-"};val rel=if(w.kind==1) w.use.relation else w.entity.relation.toLong();val source=if(w.kind==1) w.use.sourceIndex else w.entity.sourceIndex.toLong();val local=if(w.kind==1) w.use.callerOrdinal else w.entity.localIndex;val pc=if(w.kind==1) w.use.dexPc else 0xffffffffL;println("$tag $name $i $j ${z.operatorNode} $path ${w.kind} $rel $source $local $pc") }
   repeat(row.bindingCount()){ emit("BIND",it,row.binding(it)) };repeat(row.proofBindingCount()){ emit("PROOF",it,row.proofBinding(it)) }
  }
 }
 for ((name,q) in queries) {Files.writeString(out.resolve("$name.json"),q,StandardOpenOption.CREATE_NEW);val r=ScopedUseGraphExecution.execute(set,q.toByteArray());check(r.explicitScope&&r.queryId.startsWith("query:v4:")&&r.sourceCount()==2&&r.profile.scopeComplete);check(r.source(0).sourceSha256==r.source(1).sourceSha256&&r.source(0).occurrenceId!=r.source(1).occurrenceId)
  when(name) { "a"->{check(r.rowCount()==2&&r.scopeSourceCount()==1&&r.scopeSource(0)==0);held=r};"b"->check(r.rowCount()==2&&r.scopeSource(0)==1);"both"->check(r.rowCount()==4);"empty","filtered","intersection"->check(r.rowCount()==0&&r.coverage==0&&r.decision==2);"limit"->check(r.rowCount()==1&&r.executionStatus==4&&r.reason==4) };show(name,r)
 }
 val unscoped=InvokeSiteQuery(maxResults=100).toQueryIrJson().toByteArray();val old=set.queryUseGraph(unscoped);check(old.coverage==1&&!old.profile.scopeComplete);nativeFailure(3){set.queryUseGraphScopedV4(unscoped)};nativeFailure(3){set.queryUseGraph(a.toByteArray())}
 val missing=ScopedInvokeSiteQuery(listOf("missing"),maxResults=100).toQueryIrJson();nativeFailure(8){set.queryUseGraphScopedV4(missing.toByteArray())}
 val nodeOnly="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\",\"scope\":{\"slots\":[\"$slot0\"]}},\"max_results\":100}";nativeFailure(3){set.queryUseGraphScopedV4(nodeOnly.toByteArray())};nativeFailure(3){set.queryUseGraph(nodeOnly.toByteArray())}
 val v9=a.replace("\"schema_version\":1,","\"schema_version\":1,\"required_capabilities\":[\"use_streaming\"],");nativeFailure(3){set.queryUseGraphScopedV4(v9.toByteArray())}
 val v16=scope(UseTargetSymbolQuery(UseSymbolTarget.METHOD_REFERENCE,maxResults=100).toQueryIrJson(),"[\"$slot0\"]");nativeFailure(3){set.queryUseGraphScopedV4(v16.toByteArray())}
 nativeFailure(4){set.queryUseGraphScopedV4(ScopedInvokeSiteQuery(listOf(slot0),maxResults=4097).toQueryIrJson().toByteArray())};nativeFailure(4){set.queryUseGraphScopedV4(ScopedInvokeSiteQuery(listOf(slot0),maxWork=1).toQueryIrJson().toByteArray())};nativeFailure(4){set.queryUseGraphScopedV4(ByteArray(65537){32})}
 val unknownScope=scope(UseTargetReferenceQuery(UseReferenceTarget.FIELD_REFERENCE,targetWhere=EntityPredicate.flags(RawFlagOperation.CONTAINS,RawDexFlags(0)),maxResults=100).toQueryIrJson(),"[\"$slot0\"]")
 Files.writeString(out.resolve("unknown.json"),unknownScope,StandardOpenOption.CREATE_NEW)
 NativeEngine.openRawDexSet(arrayOf(unknownBytes,unknownBytes),arrayOf(slot0,slot1)).use { u -> val r=ScopedUseGraphExecution.execute(u,unknownScope.toByteArray());check(r.profile.scopeComplete&&r.coverage==1&&r.unknownRows>0);show("unknown",r) }
 set.close();check(held!!.rowCount()==2&&held!!.row(0).value.use.sourceIndex==0L);try{set.queryUseGraphScopedV4(a.toByteArray());error("closed accepted")}catch(_:IllegalStateException){}
 NativeEngine.openRawDex(bytes,"q\"\\z").use { one -> val q=ScopedInvokeSiteQuery(listOf("q\"\\z"),maxResults=100);val r=ScopedUseGraphExecution.execute(one,q);check(r.rowCount()==2&&r.profile.scopeComplete&&r.scopeSource(0)==0);nativeFailure(3){one.queryUseGraph(q.toQueryIrJson().toByteArray())} }
 val apk=zip("classes.dex" to bytes,"classes2.dex" to bytes);val resource=zip("resources.arsc" to byteArrayOf(1,2,3))
 NativeEngine.openSources(arrayOf(apk,resource),arrayOf("base","empty"),intArrayOf(2,2),booleanArrayOf(false,true)).use { s ->
  val base=ScopedUseGraphExecution.execute(s,ScopedInvokeSiteQuery(listOf("base"),maxResults=100));check(base.sourceCount()==2&&base.rowCount()==4&&base.scopeSourceCount()==2&&base.profile.scopeComplete)
  val none=ScopedUseGraphExecution.execute(s,ScopedInvokeSiteQuery(listOf("empty"),intent=QueryIntent.EXISTS,maxResults=100));check(none.sourceCount()==2&&none.scopeSourceCount()==0&&none.rowCount()==0&&none.coverage==0&&none.decision==2)
 }
 NativeEngine.openRawDex(malformedCode,"bad").use { bad -> val q=ScopedInvokeSiteQuery(listOf("bad"),maxResults=100);nativeFailure(2){ScopedUseGraphExecution.execute(bad,q)} }
 val corrupt=bytes.copyOf();corrupt[0]=0;nativeFailure(2){NativeEngine.openRawDexSet(arrayOf(corrupt),arrayOf("bad"))}
 println("PASS scoped v4 host and legacy rejection")
}
