# Method facts v0

`read_metadata` retains its checked local directories in `Facts`: lossless UTF-16
strings, type-to-string descriptor indexes, prototype return/parameter IDs and
descriptors, and separate method-reference/field-reference tables. The vector index
is the original local DEX table index. `MethodReference::type` is a prototype ID;
`FieldReference::type` is a type ID. Both have an owner type ID and a name string ID.
An external method reference remains a reference even if no definition exists in
this source. Method definitions stay in the separate `Facts::methods` directory.

The reader moves its temporary directories into the final Facts object rather than
copying them. Method text fields are read-only views into those stable directories;
Result/Batch materialization owns its own output copies. Facts is move-only and rejects
move-assignment across different PMR resources, which would invalidate its views.
The Facts object's PMR resource must
outlive all of its containers. Source owners must retain the Engine/resource until
Facts is destroyed. Treat the completed object as immutable.

`collect_method` receives the complete immutable bytes and Facts from the same
logical DEX snapshot. `method_ordinal` indexes the definition directory, not the
reference table. The caller is responsible for this source pairing; this internal
function does not recompute a strong source digest. Cross-source IDs must not be
joined without their logical DEX and source occurrence identity.

The demand mask selects string uses, invocation sites, field uses and numeric
literals. Numeric collection is an internal method-facts capability; it does not
add a public query root, ABI, or runtime value interpretation. Each literal carries
its instruction PC and opcode, a constant/arithmetical-operand kind, an explicit
32- or 64-bit width and the corresponding integer bit pattern. Narrow signed
immediates are sign-extended into that width; 32-bit patterns are stored zero-extended
in the 64-bit container. const/high16 and const-wide/high16 shift into their
specified bit positions. The original bit pattern can represent integer or
floating-point values; the collector does not guess a register type, evaluate the
arithmetic instruction, read array payload values, or imply reachability. Zero demand
returns the method's body state without reading its instructions. A native or
abstract definition reports `has_body=false`, `instruction_checked=false` and zero
decoded code units. A concrete method with requested facts runs the shared checked
decoder once; unrequested result columns remain empty. The string pool containing a
literal is never sufficient to produce a method StringUse.

`instruction_checked=true` means the decoder's documented width, local reference,
register, payload, explicit branch and try/handler boundary profile succeeded. It does not establish
full ART verification, opcode runtime types, exception type validation,
CFG/dataflow correctness or runtime dispatch. An Unsupported, corrupt,
cancelled or resource-failed decode throws and does not commit a MethodFacts result.
This method-fact collector itself does not build a reverse index, shared mutable cache, or hidden background analysis. A separate experimental snapshot-level, opt-in reverse count index is described in `docs/contracts/reverse-index-count-v1-draft.md`.

Internal demand bit `array_data` additionally extracts one raw element per
`fill-array-data` reference: instruction PC, referenced payload PC, zero-based
element index, byte width and little-endian zero-extended bits. Shared payloads
produce distinct elements for each referring PC; unreferenced payloads produce
none. No register type, execution, reachability, signedness or floating-point
interpretation is inferred. These elements are separate from `numeric_literals`
and do not change the public numeric-v7 predicate or any public ABI. The decoder
checks the whole method and exception metadata before `collect_method` returns.
Each emitted element consumes one additional payload/validation work unit per
reference; errors, cancellation and allocation failures do not return partial facts.

Returned facts own only their PMR vectors of integer IDs/PCs/opcodes. They do not
retain bytes, source objects, or borrowed text views. The result resource must
outlive the result. Resolving symbols later requires the matching Facts owner to
remain alive. Multiple calls may use the same immutable input concurrently, with
separate result resources or a thread-safe shared resource.

`switch_targets` is an internal opt-in method fact demand. It returns only the
checked explicit packed/sparse case keys and local destination PCs, with the
referring instruction and payload identity. Shared payload references remain
distinct. It does not infer default paths, reachability or executable CFG edges;
an absent body remains distinguishable through `has_body`, and no demand means
no decode. These records are not available through the public ABI or QueryIR.

`branch_targets` is a separate internal opt-in demand for the checked encoded
destinations of `goto`, `goto/16`, `goto/32` and conditional `if` instructions.
Each record preserves its instruction PC, opcode, checked local destination PC,
and unconditional/conditional classification. Each emitted record adds one
validation work unit; unrequested branches are not materialized and do not alter
the default work count. The record does not describe conditional fallthrough,
switch cases, exception handlers, reachability, runtime values or a complete CFG.
It adds no public ABI or QueryIR capability.

Invocation domains are preserved: normal invokes contain a method reference;
polymorphic invokes contain method plus extra prototype references; custom invokes
contain a call-site reference. They are not replaced by a guessed runtime target.
Call-site and method-handle tables receive structural validation during metadata
reading; full bootstrap signatures and handle target semantics remain outside
this profile.

`tests/fixtures/generators/facts_cases.py` creates an original DEX with fixed semantic
expectations (PC 0 string, PC 2 external method reference, PC 5 field), a quiet method,
native/abstract definitions and a literal used only by the string pool. It also
emits a structural 038 custom/polymorphic fixture; the latter is explicitly not an
ART/bootstrap-type acceptance sample. The fixture JSON expectations are derived
from the authored instruction words, never from decoder output.

The standalone MSVC ASan test exercised raw DEX metadata and method collection,
the original string/invoke/field demand and no-body/cancellation/error states, retained symbol directories, external
references, default-PMR-disabled accounting/reclamation and concurrent read-only
collection. This is a portable core milestone, not a complete QueryIR or BIL rule
implementation, an APK intake proof or an Android runtime result.

`MethodFacts::requested_mask` retains the exact successful demand and
`availability(single_bit)` distinguishes not requested, a definition without a
body, and a requested checked fact column. A returned checked column may be
empty, while an unrequested empty vector conveys no absence. The unknown state covers a requested body whose instruction check is absent.
The method assumes an unmodified successful collector result; it cannot validate
arbitrary caller-constructed or mutated public C++ fields. Invalid, combined or
unsupported availability bits throw. A failed/cancelled decode returns
no result. This is internal C++ only; it changes internal struct layout and does
not alter the public C ABI or validate runtime resolution or ART.

`symbols::classify_method_ref` is an internal constant-time classification for one
checked immutable Facts object: local definition with body, local definition
without body, or no definition in that occurrence. Invalid references and
inconsistent mapping are distinguished from absence. It does not inspect code
facts or imply anything about another DEX, runtime dispatch, or ART. The entity
reference path uses this classification while preserving the public rule that
method_refs never expose code_offset. There is no new C ABI.

`method_constants` is an explicit internal method-fact demand for local handle
and method-type constants; each returned fact retains opcode, PC, destination,
domain and local index. No demand is not known empty; no-body remains distinct.
The existing shared FactsCache rejects plans with this demand because it only
copies the four prior eligible kinds. No public QueryIR or ABI is added.
