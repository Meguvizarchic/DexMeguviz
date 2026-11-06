package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
/** Static fixture on host JVM/JNI; no ART. */
public fun main(args:Array<String>){
 val dex=Files.readAllBytes(Path.of(args[0]));val target="Lfixture/MethodTypeCases\$Target;"
 val where=MethodTypePredicate.all(
  MethodTypePredicate.typesAll(MethodTypeTarget(StaticTextMatch(TextOperation.EXACT,target),TypeUseOpcode.NEW_INSTANCE),MethodTypeTarget(StaticTextMatch(TextOperation.EXACT,target))),
  MethodTypePredicate.stringsAll(StaticTextMatch(TextOperation.EXACT,"needle")),
  MethodTypePredicate.invokesAll(InvokeTarget(name=StaticTextMatch(TextOperation.EXACT,"sink"))),
  MethodTypePredicate.fieldsAll(FieldTarget(name=StaticTextMatch(TextOperation.EXACT,"field"),access=FieldUseAccess.WRITE)))
 val query=MethodTypeQuery(where,maxResults=64,maxWork=1000000)
 fun checkRows(r:MethodTypeResult,count:Int){check(r.queryId.startsWith("query:v22:")&&r.rowCount()==count);repeat(r.rowCount()){i->val row=r.row(i);check(row.name=="together");val ws=(0 until row.witnessCount()).map{row.witness(it)};check(ws.count{it.kind==15L}==2&&ws.filter{it.kind==15L}.all{it.dexPc==8L&&it.targetDescriptor==target});check(ws.map{it.kind}.toSet()==setOf(2L,3L,4L,15L))}}
 NativeEngine.openRawDex(dex,"one").use{snap->checkRows(MethodTypeExecution.execute(snap,query),1)
  val emptyAll=MethodTypeQuery(MethodTypePredicate.typesAll(),maxResults=64);val all=MethodTypeExecution.execute(snap,emptyAll);check(all.queryId.startsWith("query:v22:")&&all.rowCount()==all.totalMethods)
  val emptyAny=MethodTypeQuery(MethodTypePredicate.typesAny(),maxResults=64);val none=MethodTypeExecution.execute(snap,emptyAny);check(none.queryId.startsWith("query:v22:")&&none.rowCount()==0)
  MethodTypeExecution.startJob(snap,emptyAll,16,2,0).use{job->var count=0;while(true){val poll=job.next(15000);if(poll.kind==2)break;check(poll.kind==0);count+=poll.batch.rowCount()};check(job.waitFor(15000).terminal&&count==all.totalMethods)}
  try{snap.queryMethods(query.toQueryIrJson().toByteArray());error("old entry accepted v22")}catch(e:NativeEngine.NativeFailure){check(e.status==3)}
  MethodTypeExecution.startJob(snap,query,1,2,0).use{job->var count=0;while(true){val poll=job.next(15000);if(poll.kind==2)break;check(poll.kind==0);checkRows(poll.batch,1);count++};check(job.waitFor(15000).terminal&&count==1)}
 }
 NativeEngine.openRawDexSet(arrayOf(dex,dex),arrayOf("one","two")).use{snap->checkRows(MethodTypeExecution.execute(snap,query),2);checkRows(MethodTypeExecution.execute(snap,MethodTypeQuery(where,maxResults=64,maxWork=1000000,slots=listOf("one"))),1)}
 println("PASS host Kotlin/JNI method type combination, same event reuse, scopes and Job")
}
