package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path

private fun expectInvalid(block: () -> Unit) {
    try { block(); error("invalid graph accepted") } catch (_: IllegalArgumentException) { }
}
private fun result(snapshot: NativeEngine.SourceSetSnapshot, name: String, query: GraphQuery, manual: String) {
    val typed = TypedGraphQueryExecution.execute(snapshot, query)
    val expected = GraphQueryExecution.execute(snapshot, manual.toByteArray(Charsets.UTF_8))
    check(typed.queryId == expected.queryId && typed.rowCount() == expected.rowCount() &&
          typed.unknownRows == expected.unknownRows && typed.coverage == expected.coverage && typed.decision == expected.decision)
    println("CASE\t$name\t${typed.queryId}\t${typed.rowCount()}\t${typed.unknownRows}\t${query.toQueryIrJson()}")
}
fun main(args: Array<String>) {
    val dex=Files.readAllBytes(Path.of(args[0]))
    NativeEngine.openRawDexSet(arrayOf(dex,dex),arrayOf("one","two")).use { snapshot ->
        val m=GraphExpression.scan(EntityRelation.METHOD_DEFS)
        val c=GraphExpression.scan(EntityRelation.CLASS_DEFS)
        val f=GraphExpression.scan(EntityRelation.FIELD_DEFS)
        val join=GraphExpression.join(GraphExpression.label(m,"method"),c,GraphJoinKey.LOCAL_OWNER)
        result(snapshot,"join",GraphQuery(join),"""{"schema_version":1,"relation":{"op":"join","on":"local_owner","left":{"op":"label","label":"method","input":{"op":"scan","relation":"method_defs","where":true}},"right":{"op":"scan","relation":"class_defs","where":true}},"intent":"enumerate","max_results":4096,"max_work":100000000}""")
        val semi=GraphExpression.semiJoin(m,c,GraphJoinKey.LOCAL_OWNER)
        result(snapshot,"semi",GraphQuery(semi),"""{"schema_version":1,"relation":{"op":"semi_join","on":"local_owner","left":{"op":"scan","relation":"method_defs","where":true},"right":{"op":"scan","relation":"class_defs","where":true}},"intent":"enumerate","max_results":4096,"max_work":100000000}""")
        val u=GraphExpression.distinct(GraphExpression.union(GraphSetSemantics.BAG,GraphIdentity.TUPLE,m,m))
        result(snapshot,"union",GraphQuery(u),"""{"schema_version":1,"relation":{"op":"distinct","identity":"tuple","input":{"op":"union","semantics":"bag","identity":"tuple","inputs":[{"op":"scan","relation":"method_defs","where":true},{"op":"scan","relation":"method_defs","where":true}]}},"intent":"enumerate","max_results":4096,"max_work":100000000}""")
        val group=GraphExpression.groupByOwner(listOf(GraphExpression.label(f,"F"),GraphExpression.label(m,"M")),1,4,listOf("F","M"),GraphRolePolicy.DISTINCT)
        result(snapshot,"group",GraphQuery(group),"""{"schema_version":1,"relation":{"op":"group_by_owner","inputs":[{"op":"label","label":"F","input":{"op":"scan","relation":"field_defs","where":true}},{"op":"label","label":"M","input":{"op":"scan","relation":"method_defs","where":true}}],"min":1,"max":4,"required_roles":["F","M"],"role_policy":"distinct"},"intent":"enumerate","max_results":4096,"max_work":100000000}""")
        val rf=GraphPredicate.reflectionFlags(RawFlagOperation.CONTAINS,ReflectionFlags(1))
        val filtered=GraphExpression.filter(GraphExpression.scan(EntityRelation.FIELD_REFS),rf)
        val reflect=GraphQuery(filtered)
        result(snapshot,"reflection",reflect,"""{"schema_version":1,"relation":{"op":"filter","input":{"op":"scan","relation":"field_refs","where":true},"where":{"flags":{"domain":"reflection","mode":"contains","value":1}}},"intent":"enumerate","max_results":4096,"max_work":100000000,"required_capabilities":["reflection_flags_static","reflection_relational"]}""")
        check(TypedGraphQueryExecution.execute(snapshot,reflect).unknownRows>0)
        val rawFlag=GraphPredicate.from(EntityPredicate.flags(RawFlagOperation.CONTAINS,RawDexFlags(1)))
        val mixed=GraphPredicate.all(rawFlag,GraphPredicate.not(GraphPredicate.reflectionFlags(RawFlagOperation.ANY,ReflectionFlags(0))))
        val mixedQuery=GraphQuery(GraphExpression.scan(EntityRelation.METHOD_REFS,mixed))
        result(snapshot,"mixed",mixedQuery,"""{"schema_version":1,"relation":{"op":"scan","relation":"method_refs","where":{"all":[{"flags_contains":1},{"not":{"flags":{"domain":"reflection","mode":"any","value":0}}}]}},"intent":"enumerate","max_results":4096,"max_work":100000000,"required_capabilities":["reflection_flags_static","reflection_relational"]}""")
        val e=GraphPredicate.from(EntityPredicate.text(EntityTextField.NAME,TextOperation.EXACT,"abstractMethod"))
        val q=GraphQuery(GraphExpression.scan(EntityRelation.METHOD_DEFS,e),QueryIntent.EXISTS)
        result(snapshot,"exists",q,"""{"schema_version":1,"relation":{"op":"scan","relation":"method_defs","where":{"name":{"op":"exact","value":"abstractMethod","ascii_case_insensitive":false}}},"intent":"exists","max_results":4096,"max_work":100000000}""")
        TypedGraphQueryExecution.startJob(snapshot,reflect,1,1,0).use { job ->
            var count=0
            while(true){val poll=job.next(10000);if(poll.kind==2)break;check(poll.kind==0);count+=poll.batch.rowCount()}
            val status=job.waitFor(10000);val expected=TypedGraphQueryExecution.execute(snapshot,reflect)
            check(status.terminal && status.executionStatus==0 && status.candidateCount==count && count==expected.rowCount() && status.unknownRows==expected.unknownRows)
        }
        expectInvalid { GraphExpression.label(m,"bad\"label") }
        expectInvalid { GraphExpression.join(m,f,GraphJoinKey.SAME_ENTITY) }
        expectInvalid { GraphExpression.groupByOwner(listOf(c)) }
        expectInvalid { GraphExpression.groupByOwner(listOf(f),requiredRoles=listOf("x","x")) }
        expectInvalid { GraphExpression.scan(EntityRelation.STRING_VALUES,rf) }
        expectInvalid { GraphExpression.union(GraphSetSemantics.BAG,GraphIdentity.TUPLE,m,f) }
        expectInvalid { GraphQuery(m,maxResults=0) }
        expectInvalid { GraphExpression.label(m,"a".repeat(65)) }
        var deep=m
        repeat(31){deep=GraphExpression.label(deep,"x")}
        expectInvalid { GraphExpression.label(deep,"x") }
    }
    println("PASS typed graph v3/v14 JNI and builder boundaries")
}

