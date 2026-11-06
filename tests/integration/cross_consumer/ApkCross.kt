package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    val stored=Files.readAllBytes(Path.of(args[0]));val resource=Files.readAllBytes(Path.of(args[1]));val deflated=Files.readAllBytes(Path.of(args[2]))
    val all=MethodPredicate.text(MethodTextField.NAME,TextOperation.CONTAINS,"")
    val locate=MethodPredicate.text(MethodTextField.NAME,TextOperation.EXACT,"locate")
    val absent=MethodPredicate.text(MethodTextField.NAME,TextOperation.EXACT,"absent")
    val cases=listOf("enumerate" to MethodQuery(all),"unique-locate" to MethodQuery(locate,QueryIntent.UNIQUE),
        "unique-absent" to MethodQuery(absent,QueryIntent.UNIQUE),"exists-locate" to MethodQuery(locate,QueryIntent.EXISTS),
        "exists-absent" to MethodQuery(absent,QueryIntent.EXISTS))
    for ((name,inputs,allow) in listOf(Triple("stored-resource",arrayOf(stored,resource),booleanArrayOf(false,true)),
                                       Triple("deflate-repeat",arrayOf(deflated,deflated),booleanArrayOf(false,false)))) {
        NativeEngine.openSources(inputs,arrayOf("base","other"),intArrayOf(NativeEngine.SOURCE_APK,NativeEngine.SOURCE_APK),allow).use { snapshot ->
            val info=snapshot.info();check(!info.sourceScopeComplete && info.inputCount()==2 && info.sourceCount()==if(name=="stored-resource")3 else 6)
            repeat(info.sourceCount()){i->val s=info.source(i)
                println("SOURCE\t$name\t${info.snapshotId}\t${s.sourceIndex}\t${s.inputIndex}\t${s.slot}\t${s.sourceSha256}\t${s.contentId}\t${s.occurrenceId}\t${s.logicalDexId}\t${s.archiveEntryName}\t${s.archiveEntryIndex}")
            }
            for ((label,query) in cases){val result=QueryExecution.execute(snapshot,query)
                println("CASE\t$name\t$label\t${result.queryId}\t${result.snapshotId}\t${result.executionStatus}\t${result.coverage}\t${result.decision}\t${result.reason}\t${result.candidateCount()}\t${result.visitedMethods}\t${result.totalMethods}\t${query.toQueryIrJson()}")
                repeat(result.candidateCount()){i->val r=result.candidate(i)
                    check(listOf(r.owner,r.name,r.prototype,r.sourceSlot,r.occurrenceId).all{it!=null&&it.all{c->c.code in 32..126&&c!='\t'}})
                    println("ROW\t$name\t$label\t${r.sourceIndex}\t${r.inputIndex}\t${r.methodIndex}\t${r.accessFlags}\t${r.declarationOffset}\t${r.codeOffset}\t${r.owner}\t${r.name}\t${r.prototype}\t${r.sourceSlot}\t${r.occurrenceId}")
                }
            }
        }
    }
    val corrupted=Files.readAllBytes(Path.of(args[3]))
    try {
        NativeEngine.openSources(arrayOf(stored,corrupted),arrayOf("base","other"),intArrayOf(NativeEngine.SOURCE_APK,NativeEngine.SOURCE_APK),booleanArrayOf(false,false)).close()
        error("corrupt APK accepted")
    } catch(e:NativeEngine.NativeFailure) { check(e.status==2);println("REJECT\tbad-crc\t${e.status}") }
}
