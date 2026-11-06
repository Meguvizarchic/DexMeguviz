package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

private fun invalid(block: () -> Unit) {
    try { block(); error("expected IllegalArgumentException") } catch (_: IllegalArgumentException) { }
}
fun main(args: Array<String>) {
    check(args.size == 6)
    val fixtures = Array(5) { Files.readAllBytes(Path.of(args[it])) }
    val output = Path.of(args[5])
    invalid { UseTargetReferenceQuery(UseReferenceTarget.FIELD_REFERENCE,
        useWhere = UseEventPredicate.targetDomain(UseEventTargetDomain.METHOD_REFERENCE)) }
    invalid { UseTargetReferenceQuery(UseReferenceTarget.STRING_VALUE,
        targetWhere = EntityPredicate.text(EntityTextField.OWNER, TextOperation.EXACT, "x")) }
    invalid { UseTargetReferenceQuery(UseReferenceTarget.METHOD_REFERENCE, maxResults = 0) }
    invalid { UseTargetReferenceQuery(UseReferenceTarget.METHOD_REFERENCE, maxWork = 0) }
    val long = UseTargetReferenceQuery(UseReferenceTarget.STRING_VALUE,
        targetWhere = EntityPredicate.text(EntityTextField.VALUE, TextOperation.EXACT, "x".repeat(20000))).toQueryIrJson()
    check(long.length <= 65536 && long.all { it.code < 128 })
    val cases = mutableListOf<Triple<String,Int,UseTargetReferenceQuery>>()
    for ((label,index,target) in listOf(Triple("method",0,UseReferenceTarget.METHOD_REFERENCE),
            Triple("field",1,UseReferenceTarget.FIELD_REFERENCE),Triple("string",2,UseReferenceTarget.STRING_VALUE))) {
        for (direction in UseSymbolDirection.entries) for (join in UseSymbolJoin.entries) {
            val suffix = (if (direction == UseSymbolDirection.USE_FIRST) "use" else "target") +
                (if (join == UseSymbolJoin.JOIN) "_join" else "_semi")
            cases += Triple("${label}_$suffix",index,UseTargetReferenceQuery(target,direction=direction,join=join,maxResults=100))
        }
    }
    cases += Triple("custom_unmatched",0,UseTargetReferenceQuery(UseReferenceTarget.METHOD_REFERENCE,
        useWhere=UseEventPredicate.targetDomain(UseEventTargetDomain.CALL_SITE),maxResults=100))
    cases += Triple("poly",0,UseTargetReferenceQuery(UseReferenceTarget.METHOD_REFERENCE,
        useWhere=UseEventPredicate.targetDomain(UseEventTargetDomain.METHOD_AND_PROTO),maxResults=100))
    cases += Triple("utf16",3,UseTargetReferenceQuery(UseReferenceTarget.STRING_VALUE,
        targetWhere=EntityPredicate.text(EntityTextField.VALUE,TextOperation.EXACT,"used\u0000\ud800xy"),maxResults=100))
    cases += Triple("unknown_flags",4,UseTargetReferenceQuery(UseReferenceTarget.FIELD_REFERENCE,
        targetWhere=EntityPredicate.flags(RawFlagOperation.CONTAINS,RawDexFlags(0)),maxResults=100))
    cases += Triple("mixed_sources",5,UseTargetReferenceQuery(UseReferenceTarget.FIELD_REFERENCE,maxResults=100))
    for ((label,index,query) in cases) {
        val json=query.toQueryIrJson();check(json.all { it.code < 128 } && json.contains("\"target_ref\""))
        Files.writeString(output.resolve("$label.query.json"),json,StandardOpenOption.CREATE_NEW)
        val selected=if(index==5) arrayOf(fixtures[1],fixtures[4]) else arrayOf(fixtures[index],fixtures[index])
        NativeEngine.openRawDexSet(selected,arrayOf("one","two")).use { snapshot ->
            val r=TypedUseTargetReferenceExecution.execute(snapshot,query)
            check(r.queryId.startsWith("query:v4:") && !r.profile.scopeComplete && r.sourceCount()==2)
            check((r.source(0).sourceSha256==r.source(1).sourceSha256)==(index!=5) && r.source(0).occurrenceId!=r.source(1).occurrenceId)
            if(label=="custom_unmatched") check(r.rowCount()==0)
            if(label=="poly") check(r.rowCount()==2)
            if(label=="unknown_flags") check(r.unknownRows>0)
            println("CASE $label ${r.queryId} ${r.rowCount()} ${r.executionStatus} ${r.coverage} ${r.decision} ${r.reason} ${r.unknownRows} ${if(index==5) "1,4" else "$index,$index"}")
            repeat(r.rowCount()) { i ->
                val row=r.row(i);check(row.linkCount()==1);val link=row.link(0)
                check(link.left.sourceIndex==link.right.sourceIndex && link.key==5L)
                println("LINK $label $i ${link.key} ${link.left.sourceIndex} ${link.left.localIndex} ${link.left.dexPc} ${link.right.sourceIndex} ${link.right.localIndex} ${link.right.dexPc}")
                if(row.value.kind==1){val u=row.value.use;println("USE $label $i ${u.sourceIndex} ${u.callerOrdinal} ${u.callerMethodRef} ${u.dexPc} ${u.opcode} ${u.targetDomain} ${u.targetIndex} ${u.extraProto}")}
                fun bindingLine(tag:String, binding:UseGraphResult.Binding) {
                    val v=binding.value;val path=binding.path().joinToString("") { if(it.toInt()==0) "L" else "R" }.ifEmpty { "-" }
                    val rel=if(v.kind==1) v.use.relation else v.entity.relation.toLong()
                    val src=if(v.kind==1) v.use.sourceIndex else v.entity.sourceIndex.toLong()
                    val local=if(v.kind==1) v.use.callerOrdinal else v.entity.localIndex
                    val pc=if(v.kind==1) v.use.dexPc else 0xffffffffL
                    println("$tag $label $i $path $rel $src $local $pc ${if(tag=="PROOF") binding.operatorNode else 0}")
                }
                repeat(row.bindingCount()) { bindingLine("BIND",row.binding(it)) }
                repeat(row.proofBindingCount()) { bindingLine("PROOF",row.proofBinding(it)) }
            }
        }
    }
    NativeEngine.openRawDexSet(arrayOf(fixtures[0],fixtures[0]),arrayOf("one","two")).use { snapshot ->
        val predicate=UseEventPredicate.targetDomain(UseEventTargetDomain.METHOD_AND_PROTO)
        val local=TypedUseTargetReferenceExecution.execute(snapshot,UseTargetReferenceQuery(UseReferenceTarget.METHOD_REFERENCE,useWhere=predicate,maxResults=100))
        val symbol=TypedUseTargetSymbolExecution.execute(snapshot,UseTargetSymbolQuery(UseSymbolTarget.METHOD_REFERENCE,useWhere=predicate,maxResults=100))
        check(local.rowCount()==2 && symbol.rowCount()==4 && local.queryId.startsWith("query:v4:") && symbol.queryId.startsWith("query:v16:"))
        check((0 until symbol.rowCount()).any { symbol.row(it).link(0).left.sourceIndex != symbol.row(it).link(0).right.sourceIndex })
        println("COMPARE local=${local.rowCount()} symbol=${symbol.rowCount()}")
    }
    NativeEngine.openRawDex(fixtures[0],"single").use { snapshot ->
        val query=UseTargetReferenceQuery(UseReferenceTarget.METHOD_REFERENCE,maxResults=100)
        val r=TypedUseTargetReferenceExecution.execute(snapshot,query)
        check(r.queryId.startsWith("query:v4:") && !r.profile.scopeComplete && r.sourceCount()==1)
        val scoped=query.toQueryIrJson().replace("\"schema_version\":1,","\"schema_version\":1,\"scope\":{\"slots\":[\"single\"]},")
        try { UseGraphQueryExecution.execute(snapshot,scoped.toByteArray(Charsets.UTF_8)); error("scope should be rejected") }
        catch (error: NativeEngine.NativeFailure) { check(error.status==3) }

        try { TypedUseTargetReferenceExecution.execute(snapshot,UseTargetReferenceQuery(UseReferenceTarget.METHOD_REFERENCE,maxResults=4097)); error("JNI cap should reject") }
        catch (error: NativeEngine.NativeFailure) { check(error.status==4) }
        println("SINGLE ${r.rowCount()}")
    }
    println("PASS typed v4 target reference")
}
