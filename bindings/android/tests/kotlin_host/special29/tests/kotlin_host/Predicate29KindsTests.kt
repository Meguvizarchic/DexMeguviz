package io.github.jichuo1.dexmeguviz

fun main() {
    val p = MethodPredicate
    val cases = listOf(
        "constructor" to p.constructor(),
        "clinit" to p.classInitializer(),
        "normal" to p.normalMethod(),
        "owner-exact-public" to p.ownerFlags(RawFlagOperation.EXACT, RawDexFlags(1)),
        "owner-exact-final" to p.ownerFlags(RawFlagOperation.EXACT, RawDexFlags(17)),
        "owner-exact-absent" to p.ownerFlags(RawFlagOperation.EXACT, RawDexFlags(0)),
        "owner-any-final" to p.ownerFlags(RawFlagOperation.ANY, RawDexFlags(16)),
        "owner-any-absent" to p.ownerFlags(RawFlagOperation.ANY, RawDexFlags(32)),
        "owner-any-zero" to p.ownerFlags(RawFlagOperation.ANY, RawDexFlags(0)),
        "owner-contains-zero" to p.ownerFlags(RawFlagOperation.CONTAINS, RawDexFlags(0))
    )
    for ((label, predicate) in cases) println("$label\t${MethodQuery(predicate).toQueryIrJson()}")
    System.err.println("PASS method-kind and owner-flag Kotlin construction")
}
