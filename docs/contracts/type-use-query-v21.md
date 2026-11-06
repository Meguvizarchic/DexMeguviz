# Static type-use relation v21

This opt-in profile records DEX type-reference instructions, not runtime class resolution, successful allocation, ART verification, reachability, object initialization or BIL compatibility. `required_capabilities:["type_uses"]` is required for an object relation containing `type_uses`; other existing profiles and default metadata-open semantics do not change. The canonical ID domain is `DexMeguviz:QueryIR:type-uses-v21` and the public prefix is `query:v21:`. The capability bit is 1073741824 and the decoder demand is 256.

## Event and source identity

A checked method emits one record for each occurrence of opcode 0x1c (const-class), 0x1f (check-cast), 0x20 (instance-of), 0x22 (new-instance), 0x23 (new-array), 0x24 (filled-new-array) and 0x25 (filled-new-array/range). The raw opcode is authoritative. The local type index is checked against the same logical DEX type table, and the descriptor preserves its UTF-16 units. Facts do not infer that the operand has the runtime kind expected by an ART verifier. `extra_proto` remains UINT32_MAX. A no-body method contributes no instruction events.

Identity is `(source_index, relation=type_uses, caller_ordinal, dex_pc)`; PC is a 16-bit DEX code-unit offset. Records additionally carry caller method-ref, code offset, opcode, target domain `type_ref`, local type index and descriptor. Repeated same-target instructions and identical DEX bytes in different occurrences remain separate. Scope completeness is relative to explicit selected static inputs, not class-loader completeness or origin authentication.

A `type_uses` object scan supports ordinary use predicates and `target_descriptor` text matching with the existing UTF-16 exact/contains/prefix rules. Existing `scan`, `filter`, `label`, same-family `union`/`distinct` and compatible joins apply: `caller` joins method_defs and type_uses on source and caller ordinal; `target_ref` joins type_uses and type_refs on source and local type index. Other existing legal relational graph constraints continue. A `not` predicate filters existing events and does not establish method-level absence. Advanced/inherited/numeric/reflection/target-symbol and streaming combinations are rejected until explicitly supported.

## Budget, errors and cancellation

The decoder performs a complete checked walk of each method before the executor consumes its event records. New type records are allocated only under their explicit demand; every emission consumes decoder validation work. A dedicated per-method callback allows the evaluator to discard nonmatching raw records instead of accumulating every source event; every event, predicate comparison and matched result still consumes query work and Engine-controlled PMR memory. Per-method raw record limits, output/intermediate row limits, descriptor length, JNI wire and queue limits remain independent. Unknown opcodes, malformed bounds, work/record limits, allocator failure and cancellation never become a completed empty result.

The v21 Job path does not publish during scan: it first completes the evaluator, then materializes and queues bounded provisional batches. Cancellation, deadline or memory failure during later materialization/queueing may leave already-delivered provisional batches; clients must consume to EOS and check the terminal lifecycle, coverage, decision and error. The selected source scope and exact result limit remain separate from total APK or runtime completeness.

## ABI and bridges

Existing numeric relation values 0–9 and target domains 0–4 retain their meanings; type_uses=10, type_ref=5 and type-use witness=15 are appended. Existing v2 result/Job accessors return Unsupported for v21; new v3 accessors supply type-use values and a Result/Batch-owned borrowed UTF-16 target descriptor. Invalid output sizes are rejected before writes. Other profiles retain their previous getter behavior. No reverse index is implicitly built.

CLI uses the same QueryIR and prints source-local use identity and descriptor. Android has independent `queryTypeUseGraph`/`startTypeUseGraphJob` entry points; old entry points reject v21. The v21 private copied use-graph wire has magic 0x58474d44 and includes the target descriptor; old wires are unchanged. Kotlin `TypeUseQuery`, `TypeUsePredicate` and its new enums do not change existing Kotlin enum ordinals. JNI limits remain JSON 64 KiB, copied wire 8 MiB, max_results 4096 and max_work 100000000; Kotlin runtime remains host-provided. Host JVM, Android cross-build and R8 evidence do not prove Android/ART runtime behavior.

For a type-use witness, `reference_index` is the same source-local type ID and the numeric `reference_kind` field is reserved as 0; the witness kind identifies it as a type reference. CLI renders that contextual domain as `type_ref` and reports the source-local identity domain including caller ordinal and PC.
