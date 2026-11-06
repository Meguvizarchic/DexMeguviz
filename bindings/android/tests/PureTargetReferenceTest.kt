package io.github.jichuo1.dexmeguviz
private fun invalid(f: () -> Unit) { try { f(); error("expected failure") } catch (_: IllegalArgumentException) { } }
fun main() {
 for (target in UseReferenceTarget.entries) for (direction in UseSymbolDirection.entries) for (join in UseSymbolJoin.entries) {
  val text=UseTargetReferenceQuery(target,direction=direction,join=join).toQueryIrJson()
  check(text.contains("\"target_ref\"") && !text.contains("use_target_symbol") && text.all { it.code < 128 })
 }
 invalid { UseTargetReferenceQuery(UseReferenceTarget.STRING_VALUE,useWhere=UseEventPredicate.targetDomain(UseEventTargetDomain.CALL_SITE)) }
 invalid { UseTargetReferenceQuery(UseReferenceTarget.METHOD_REFERENCE,targetWhere=EntityPredicate.text(EntityTextField.TYPE,TextOperation.EXACT,"x")) }
 invalid { UseTargetReferenceQuery(UseReferenceTarget.FIELD_REFERENCE,maxResults=0) }
 invalid { UseTargetReferenceQuery(UseReferenceTarget.FIELD_REFERENCE,maxWork=0) }
 invalid { UseTargetReferenceQuery(UseReferenceTarget.STRING_VALUE,targetWhere=EntityPredicate.text(EntityTextField.VALUE,TextOperation.EXACT,"x".repeat(65536))).toQueryIrJson() }
 val special=UseTargetReferenceQuery(UseReferenceTarget.STRING_VALUE,targetWhere=EntityPredicate.text(EntityTextField.VALUE,TextOperation.EXACT,"a\u0000\ud800x")).toQueryIrJson()
 check(special.all { it.code<128 } && (special.contains("u16") || special.contains("\\ud800", ignoreCase=true)))
 println("PASS pure JVM typed target reference")
}
