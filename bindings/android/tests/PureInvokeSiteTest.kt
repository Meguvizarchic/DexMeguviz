package io.github.jichuo1.dexmeguviz
private fun invalidInvoke(f:()->Unit){try{f();error("expected invalid")}catch(_:IllegalArgumentException){}}
fun main(){
 for(domain in listOf(UseEventTargetDomain.METHOD_REFERENCE,UseEventTargetDomain.METHOD_AND_PROTO,UseEventTargetDomain.CALL_SITE)){
  val q=InvokeSiteQuery(UseEventPredicate.targetDomain(domain)).toQueryIrJson();check(q.contains("\"invoke_sites\"")&&q.all{it.code<128})
 }
 invalidInvoke{InvokeSiteQuery(UseEventPredicate.targetDomain(UseEventTargetDomain.STRING_VALUE))}
 invalidInvoke{InvokeSiteQuery(maxResults=0)};invalidInvoke{InvokeSiteQuery(maxWork=0)}
 invalidInvoke{InvokeSiteQuery(UseEventPredicate.text(UseEventTextField.CALLER_NAME,TextOperation.EXACT,"x".repeat(65536))).toQueryIrJson()}
 val u=InvokeSiteQuery(UseEventPredicate.text(UseEventTextField.CALLER_NAME,TextOperation.EXACT,"x\u0000\ud800y")).toQueryIrJson();check(u.all{it.code<128})
 println("PASS pure JVM invoke-site query")
}
