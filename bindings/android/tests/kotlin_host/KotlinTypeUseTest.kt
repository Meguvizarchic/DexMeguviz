package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path

/** Fixed host JVM/JNI fixture; not ART execution. */
public fun main(args:Array<String>){
 val dex=Files.readAllBytes(Path.of(args[0]));val target="Lfixture/TypeUses\$Parent;"
 val where=TypeUsePredicate.all(TypeUsePredicate.opcode(TypeUseOpcode.NEW_INSTANCE),TypeUsePredicate.targetDescriptor(TextOperation.EXACT,target))
 val query=TypeUseQuery(where=where,maxResults=100,maxWork=1000000)
 fun checkRows(result:UseGraphResult,count:Int){
  check(result.queryId.startsWith("query:v21:")&&result.rowCount()==count)
  repeat(result.rowCount()){i->val row=result.row(i);check(row.value.kind==1);val use=row.value.use;check(use.relation==10L&&use.targetDomain==5L&&use.opcode==34L&&use.targetDescriptor==target);check(row.witnessCount()>0)}
 }
 NativeEngine.openRawDex(dex,"one").use { snap->
  checkRows(TypeUseExecution.execute(snap,query),2)
  try{snap.queryUseGraph(query.toQueryIrJson().toByteArray());error("old entry accepted v21")}catch(e:NativeEngine.NativeFailure){check(e.status==3)}
  val targetPredicate=EntityPredicate.text(EntityTextField.DESCRIPTOR,TextOperation.EXACT,target)
  val targetQuery=TypeUseQuery(where=TypeUsePredicate.opcode(TypeUseOpcode.NEW_INSTANCE),joinTarget=TypeUseJoinTarget.TYPE_REFERENCE,targetWhere=targetPredicate,maxResults=100,maxWork=1000000)
  checkRows(TypeUseExecution.execute(snap,targetQuery),2)
  val caller=EntityPredicate.text(EntityTextField.NAME,TextOperation.EXACT,"allocate")
  val callerQuery=TypeUseQuery(where=TypeUsePredicate.opcode(TypeUseOpcode.NEW_INSTANCE),joinTarget=TypeUseJoinTarget.CALLER_METHOD,targetWhere=caller,maxResults=100,maxWork=1000000)
  checkRows(TypeUseExecution.execute(snap,callerQuery),1)
  TypeUseExecution.startJob(snap,query,1,2,0).use { job->var count=0;while(true){val x=job.next(15000);if(x.kind==2)break;check(x.kind==0);count+=x.batch.rowCount()};val status=job.waitFor(15000);check(status.terminal&&status.executionStatus==0&&count==2)}
 }
 NativeEngine.openRawDexSet(arrayOf(dex,dex),arrayOf("one","two")).use{snap->
  checkRows(TypeUseExecution.execute(snap,query),4)
  checkRows(TypeUseExecution.execute(snap,TypeUseQuery(where=where,maxResults=100,maxWork=1000000,slots=listOf("one"))),2)
 }
 if(args.size>1){
  val arrayDex=Files.readAllBytes(Path.of(args[1]));val arrayQuery=TypeUseQuery(where=TypeUsePredicate.targetDescriptor(TextOperation.EXACT,"[Ljava/lang/Object;"),maxResults=100,maxWork=1000000)
  NativeEngine.openRawDex(arrayDex,"arrays").use{snap->
   val result=TypeUseExecution.execute(snap,arrayQuery);check(result.rowCount()==2)
   val uses=(0 until result.rowCount()).map{result.row(it).value.use};check(uses.map{it.opcode}.toSet()==setOf(0x24L,0x25L));check(uses.all{it.dexPc==0L&&it.targetIndex==3L&&it.targetDescriptor=="[Ljava/lang/Object;"})
   val bad=arrayDex.copyOf();val ranged=uses.single{it.opcode==0x25L};val at=(ranged.codeOffset+18L).toInt();bad[at]=0xff.toByte();bad[at+1]=0xff.toByte()
   NativeEngine.openRawDex(bad,"invalid").use{broken->try{TypeUseExecution.execute(broken,arrayQuery);error("invalid type accepted")}catch(e:NativeEngine.NativeFailure){check(e.status==2)}}
  }
 }
 println("PASS host Kotlin/JNI type use scan, target/caller joins, old entry and Job")
}
