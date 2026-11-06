package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    require(args.size == 1)
    val bytes = Files.readAllBytes(Path.of(args[0]))
    val external = EntityQuery(EntityRelation.FIELD_REFS, EntityPredicate.hasLocalDefinition(false))
    val one: NativeEngine.EntityCandidate
    NativeEngine.openRawDex(bytes, "single").use { snapshot ->
        val result: NativeEngine.EntityResult = QueryExecution.execute(snapshot, external)
        check(result.relation == 4 && result.coverage == 1 && result.candidateCount() == 1)
        one = result.candidate(0)
        check(one.name == "externalField" && one.definitionOffset == null && one.accessFlags == null)
        val methods = QueryExecution.execute(snapshot, MethodQuery(MethodPredicate.constant(true)))
        check(methods.candidateCount() == 1)
    }
    check(one.name == "externalField" && one.sourceSlot == "single")
    NativeEngine.openRawDexSet(arrayOf(bytes,bytes), arrayOf("a","b")).use { snapshot ->
        val result = QueryExecution.execute(snapshot, EntityQuery(EntityRelation.FIELD_DEFS))
        check(result.candidateCount() == 6 && result.candidate(0).sourceIndex == 0 && result.candidate(3).sourceIndex == 1)
        check(result.candidate(0).occurrenceId != result.candidate(3).occurrenceId)
    }
    println("PASS Kotlin typed entity bridge and method compatibility")
}
