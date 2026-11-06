package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    check(args.size == 2)
    val root=Path.of(args[0]);val out=Path.of(args[1])
    val slots=arrayOf("child","parent","object")
    val bytes=arrayOf("child.dex","parent.dex","object.dex").map { Files.readAllBytes(root.resolve(it)) }.toTypedArray()
    val query=FieldDeclarationQuery(slots.toList(),FieldDeclarationScope.INHERITED,FieldUseAccess.READ,maxResults=100)
    val json=query.toQueryIrJson();Files.writeString(out,json)
    val snapshot=NativeEngine.openRawDexSet(bytes,slots)
    try {
        for (limited in listOf(
            FieldDeclarationQuery(slots.toList(),FieldDeclarationScope.ANY,maxResults=4097),
            FieldDeclarationQuery(slots.toList(),FieldDeclarationScope.ANY,maxWork=100000001L))) {
            try { FieldDeclarationQueryExecution.execute(snapshot,limited);error("expected JNI BudgetExceeded") }
            catch (e: NativeEngine.NativeFailure) { check(e.status==4) { "unexpected JNI budget status ${e.status}" } }
        }
        val result=FieldDeclarationQueryExecution.execute(snapshot,query)
        check(result.queryId.startsWith("query:v19:") && result.rowCount()==1 && result.unknownRows==1L)
        check(result.row(0).value.use.dexPc==0L)
        val proof=(0 until result.row(0).witnessCount()).map { result.row(0).witness(it) }.filter { it.fieldDeclarationDetailPresent }
        check(proof.size==3 && proof[0].fieldDeclarationEdge==0L && proof[1].fieldDeclarationEdge==2L)
        check(proof[2].fieldDeclarationItem==1L && proof[2].entity.sourceIndex==1L && proof[2].entity.localIndex==0L)
        try { snapshot.queryUseGraph(json.toByteArray(Charsets.UTF_8)); error("old use graph unexpectedly accepted v19") }
        catch (e: NativeEngine.NativeFailure) { check(e.status==3) { "unexpected old entry status ${e.status}" } }
        try { snapshot.queryUseGraphScopedV4(json.toByteArray(Charsets.UTF_8)); error("old scoped graph unexpectedly accepted v19") }
        catch (e: NativeEngine.NativeFailure) { check(e.status==3) { "unexpected old scoped entry status ${e.status}" } }
    } finally { snapshot.close() }
    println("PASS Q08 Kotlin/JNI static field declaration and version isolation")
}
