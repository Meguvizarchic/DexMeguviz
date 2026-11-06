package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
private fun invalid(f:()->Unit){try{f();error("expected invalid")}catch(_:IllegalArgumentException){}}
private fun manual(owner:String,name:String):String {
 fun u16(x:String)=x.map{it.code}.joinToString(",","[","]")
 return "{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\",\"where\":{\"all\":[{\"caller_owner\":{\"op\":\"exact\",\"u16\":${u16(owner)}}},{\"caller_name\":{\"op\":\"exact\",\"u16\":${u16(name)}}}]}},\"max_results\":4096,\"max_work\":100000000}"
}
fun main(args:Array<String>){
 check(args.size==7);val fixtures=Array(6){Files.readAllBytes(Path.of(args[it]))};val out=Path.of(args[6]);val owner="Lfixture/Overload;";val name="same"
 invalid{InvokeSiteQuery(UseEventPredicate.targetDomain(UseEventTargetDomain.FIELD_REFERENCE))};invalid{InvokeSiteQuery(maxResults=0)};invalid{InvokeSiteQuery(maxWork=0)}
 val full=UseEventPredicate.all(UseEventPredicate.text(UseEventTextField.CALLER_OWNER,TextOperation.EXACT,owner),UseEventPredicate.text(UseEventTextField.CALLER_NAME,TextOperation.EXACT,name))
 val cases=listOf(
  Triple("overload", "0,0", InvokeSiteQuery(full)),
  Triple("mixed", "0,1", InvokeSiteQuery()),
  Triple("poly", "1,1", InvokeSiteQuery(UseEventPredicate.targetDomain(UseEventTargetDomain.METHOD_AND_PROTO))),
  Triple("custom", "1,1", InvokeSiteQuery(UseEventPredicate.targetDomain(UseEventTargetDomain.CALL_SITE))),
  Triple("two_proto", "2,2", InvokeSiteQuery(UseEventPredicate.targetDomain(UseEventTargetDomain.METHOD_AND_PROTO))),
  Triple("utf16_hit", "5,5", InvokeSiteQuery(UseEventPredicate.text(UseEventTextField.CALLER_NAME,TextOperation.EXACT,"s\ud83d\ude00"))),
  Triple("utf16_missing", "3,3", InvokeSiteQuery(UseEventPredicate.text(UseEventTextField.CALLER_NAME,TextOperation.EXACT,"used\u0000\ud800xy"),intent=QueryIntent.EXISTS)),
  Triple("empty_text", "0,0", InvokeSiteQuery(UseEventPredicate.text(UseEventTextField.CALLER_NAME,TextOperation.CONTAINS,""))),
  Triple("pc_filter", "0,0", InvokeSiteQuery(UseEventPredicate.number(UseEventNumberField.PC,0))),
  Triple("limited", "0,0", InvokeSiteQuery(maxResults=1))
 )
 for((label,selection,query) in cases){
  val ids=selection.split(',').map(String::toInt);val json=query.toQueryIrJson();check(json.all{it.code<128} && json.contains("\"invoke_sites\""));Files.writeString(out.resolve("$label.query.json"),json,StandardOpenOption.CREATE_NEW)
  NativeEngine.openRawDexSet(arrayOf(fixtures[ids[0]],fixtures[ids[1]]),arrayOf("one","two")).use { snap->
   val result=TypedInvokeSiteExecution.execute(snap,query);check(result.queryId.startsWith("query:v4:")&&!result.profile.scopeComplete&&result.sourceCount()==2)
   check(result.source(0).occurrenceId!=result.source(1).occurrenceId);if(ids[0]==ids[1])check(result.source(0).sourceSha256==result.source(1).sourceSha256) else check(result.source(0).sourceSha256!=result.source(1).sourceSha256)
   if(label=="overload"){
    check(result.rowCount()==4);val ps=(0 until result.rowCount()).map{result.row(it).value.use.prototype}.toSet();check(ps==setOf("()V","(I)V"));check((0 until result.rowCount()).map{result.row(it).value.use.callerMethodRef}.toSet().size==2)
    val old=UseGraphQueryExecution.execute(snap,manual(owner,name).toByteArray(Charsets.UTF_8));check(old.queryId==result.queryId&&old.rowCount()==result.rowCount())
    repeat(result.rowCount()){i->val a=old.row(i).value.use;val b=result.row(i).value.use;check(a.sourceIndex==b.sourceIndex&&a.callerMethodRef==b.callerMethodRef&&a.dexPc==b.dexPc&&a.targetDomain==b.targetDomain&&a.targetIndex==b.targetIndex&&a.extraProto==b.extraProto)}
    println("MANUAL ${result.queryId} ${result.rowCount()}")
   }
   if(label=="poly")check(result.rowCount()==2&&(0 until result.rowCount()).all{result.row(it).value.use.targetDomain==3L})
   if(label=="custom")check(result.rowCount()==2&&(0 until result.rowCount()).all{result.row(it).value.use.targetDomain==4L})
   if(label=="two_proto")check(result.rowCount()==4&&(0 until result.rowCount()).map{result.row(it).value.use.extraProto}.toSet()==setOf(0L,1L))
   if(label=="utf16_hit")check(result.rowCount()==4&&(0 until result.rowCount()).all{result.row(it).value.use.name=="s\ud83d\ude00"})
   if(label=="utf16_missing")check(result.rowCount()==0&&result.decision==1&&result.unknownRows==0L)
   if(label=="limited")check(result.rowCount()==1&&result.executionStatus==4&&result.coverage==1)
   println("CASE $label ${result.queryId} ${result.rowCount()} ${result.executionStatus} ${result.coverage} ${result.decision} ${result.reason} ${result.unknownRows} $selection")
   repeat(result.rowCount()){i->val row=result.row(i);check(row.value.kind==1);val u=row.value.use;println("EVENT $label $i ${u.sourceIndex} ${u.callerOrdinal} ${u.callerMethodRef} ${u.dexPc} ${u.opcode} ${u.codeOffset} ${u.targetDomain} ${u.targetIndex} ${u.extraProto} ${row.witnessCount()}")}
  }
 }
 NativeEngine.openRawDex(fixtures[1],"single").use{snap->
  val q=InvokeSiteQuery();check(TypedInvokeSiteExecution.execute(snap,q).sourceCount()==1)
  val scoped=q.toQueryIrJson().replace("\"schema_version\":1,","\"schema_version\":1,\"scope\":{\"slots\":[\"single\"]},")
  try{UseGraphQueryExecution.execute(snap,scoped.toByteArray());error("scope accepted")}catch(e:NativeEngine.NativeFailure){check(e.status==3)}
  try{TypedInvokeSiteExecution.execute(snap,InvokeSiteQuery(maxResults=4097));error("JNI limit accepted")}catch(e:NativeEngine.NativeFailure){check(e.status==4)}
 }
 NativeEngine.openRawDex(fixtures[4],"bad").use{snap->
  try{TypedInvokeSiteExecution.execute(snap,InvokeSiteQuery());error("corrupt code accepted")}
  catch(e:NativeEngine.NativeFailure){check(e.status==2)}
 }
 println("CORRUPT rejected")
 println("PASS typed invoke-site scan")
}
