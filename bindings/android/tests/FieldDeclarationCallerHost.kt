package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path

fun main(args:Array<String>) {
    check(args.size==2);val dir=Path.of(args[0]);val out=Path.of(args[1]);val slots=arrayOf("callerA","callerB","child","parent","object")
    val names=arrayOf("caller-a.dex","caller-b.dex","child.dex","parent.dex","object.dex")
    val data=names.map { Files.readAllBytes(dir.resolve(it)) }.toTypedArray()
    val snapshot=NativeEngine.openRawDexSet(data,slots)
    try {
        val field=FieldDeclarationQuery(slots.toList(),FieldDeclarationScope.INHERITED,maxResults=100)
        val method=EntityPredicate.text(EntityTextField.NAME,TextOperation.EXACT,"access")
        val join=FieldDeclarationCallerQuery(field,method,UseSymbolJoin.JOIN)
        val semi=FieldDeclarationCallerQuery(field,method,UseSymbolJoin.SEMI_JOIN)
        Files.writeString(out,join.toQueryIrJson())
        val a=TypedFieldDeclarationCallerExecution.execute(snapshot,join)
        val z=TypedFieldDeclarationCallerExecution.execute(snapshot,semi)
        check(a.queryId.startsWith("query:v19:") && a.rowCount()==4 && a.unknownRows==4L)
        check(z.queryId.startsWith("query:v19:") && z.rowCount()==2 && z.unknownRows==0L)
        for ((res,isSemi) in listOf(a to false,z to true)) for (i in 0 until res.rowCount()) {
            val row=res.row(i);check(row.value.kind==0 && row.value.entity.sourceIndex in 0L..1L && row.linkCount()==1)
            val link=row.link(0);check(link.key==4L && link.left.sourceIndex==row.value.entity.sourceIndex.toLong() && link.right.sourceIndex==row.value.entity.sourceIndex.toLong() && link.right.dexPc in listOf(0L,2L))
            val evidence=(0 until row.witnessCount()).map { row.witness(it) }.filter { it.fieldDeclarationDetailPresent }
            check(evidence.size==3 && evidence[0].entity.sourceIndex==2L && evidence[1].entity.sourceIndex==3L && evidence[2].entity.sourceIndex==3L && evidence[2].fieldDeclarationItem==1L)
            if(isSemi){check(row.proofBindingCount()==1);val proof=row.proofBinding(0).value;check(proof.kind==1 && proof.use.sourceIndex==row.value.entity.sourceIndex.toLong() && proof.use.dexPc==0L)}
            else check(row.bindingCount()==2)
        }
        try {snapshot.queryUseGraph(join.toQueryIrJson().toByteArray(Charsets.UTF_8));error("legacy entry accepted v19")}
        catch(e:NativeEngine.NativeFailure){check(e.status==3)}
        val raw=field.toQueryIrJson();check(snapshot.queryFieldDeclarationGraph(raw.toByteArray(Charsets.UTF_8)).rowCount()==4)
    } finally {snapshot.close()}
    println("PASS Q08 Kotlin caller Join/SemiJoin, path evidence and legacy v19 isolation")
}
