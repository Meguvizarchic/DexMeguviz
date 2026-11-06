package io.github.jichuo1.dexmeguviz

/** Independent dimensions from the native result; no decision is inferred from row count. */
public enum class Coverage { COMPLETE, PARTIAL }
public enum class ExecutionStatus {
    COMPLETE, INVALID_ARGUMENT, CORRUPT_INPUT, UNSUPPORTED, BUDGET_EXCEEDED,
    OUT_OF_MEMORY, INTERNAL_ERROR, CLOSED, SOURCE_MISMATCH, CANCELLED,
    DEADLINE_EXCEEDED, NOT_READY, END_OF_STREAM
}
public enum class Decision { NOT_APPLICABLE, UNDETERMINED, PROVEN_FALSE, PROVEN_TRUE }
public enum class DecisionReason { NONE, NO_MATCH, AMBIGUOUS, WITNESS, RESULT_LIMIT, SOURCE_SCOPE_INCOMPLETE, UNKNOWN_ATTRIBUTE }

/** A snapshot of already-observed values, not a native handle or a runtime binding. */
public data class QuerySummary(
    val executionStatus: ExecutionStatus,
    val coverage: Coverage,
    val decision: Decision,
    val reason: DecisionReason,
    val candidateCount: Long
) {
    init { require(candidateCount in 0L..0xffffffffL) }
}

/** One source occurrence, intentionally distinct from content and runtime loader identity. */
public data class SourceIdentity(val sourceIndex: Long, val occurrenceId: String, val contentId: String) {
    init {
        require(sourceIndex in 0L..0xffffffffL)
        require(occurrenceId.isNotEmpty() && contentId.isNotEmpty())
    }
}
