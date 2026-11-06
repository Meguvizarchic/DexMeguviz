package io.github.jichuo1.dexmeguviz
private fun invalid(f: () -> Unit) { try { f(); error("expected IllegalArgumentException") } catch (_: IllegalArgumentException) { } }
fun main() {
 val source=mutableListOf("input:0:a.dex", "input:1:a.dex")
 val q=ScopedInvokeSiteQuery(source);source.clear();check(q.toQueryIrJson().contains("input:0:a.dex") && q.toQueryIrJson().contains("input:1:a.dex"))
 val encoded=ScopedInvokeSiteQuery(listOf("q\"\\z")).toQueryIrJson();check(encoded.contains("q\\\"\\\\z") && encoded.all { it.code<128 })
 check(ScopedInvokeSiteQuery(emptyList()).toQueryIrJson().contains("\"slots\":[]"))
 invalid { ScopedInvokeSiteQuery(listOf("same","same")) };invalid { ScopedInvokeSiteQuery(listOf("")) }
 invalid { ScopedInvokeSiteQuery(listOf("contains space")) };invalid { ScopedInvokeSiteQuery(listOf("x".repeat(129))) }
 invalid { ScopedInvokeSiteQuery(List(9) { "slot$it" }) };invalid { ScopedInvokeSiteQuery(listOf("nonascii-\u00e9")) }
 invalid { ScopedInvokeSiteQuery(listOf("one"),UseEventPredicate.targetDomain(UseEventTargetDomain.FIELD_REFERENCE)) }
 invalid { ScopedInvokeSiteQuery(listOf("one"),maxResults=0) };invalid { ScopedInvokeSiteQuery(listOf("one"),maxWork=0) }
 println("PASS pure JVM explicit scoped use query")
}
