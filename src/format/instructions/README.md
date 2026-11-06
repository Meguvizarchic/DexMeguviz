# Checked instruction decoder scope

The decoder is an original C++20 scalar implementation. It consumes a caller-owned,
immutable byte span, a checked `code_item` offset, the DEX version, and reference
table bounds from the metadata reader. The span and PMR resource must remain valid
during the call; the resource must additionally outlive the returned result.

The supported instruction versions are 035, 037, 038, 039 and 040. Version 038
introduces custom/polymorphic invocation; method-handle/type constants require 039.
Reserved and optimized opcodes are rejected, and a version-gated opcode returns
Unsupported. No unknown opcode is treated as NOP.

The first pass establishes every instruction/payload boundary after range checks.
The second pass verifies explicit branch and switch targets against those boundaries.
Payloads have checked kinds, four-byte alignment, sizes, primitive element widths,
key ordering and target scopes. Switch targets are relative to the referring switch.
Method entry is executable, never a payload. Register bounds include wide pairs,
range arguments and the code item's outgoing-word capacity. Reference domains remain
distinct: custom calls use call-site IDs, polymorphic calls use method plus proto IDs.

Demand bits select StringUse, InvokeSite and FieldUse output. Reference/operand checks
remain enabled when a corresponding fact is not requested. The decoder itself does not build a reverse index; a separate experimental snapshot-level index is documented in `docs/contracts/reverse-index-count-v1-draft.md`.
All result payloads use the supplied PMR resource. Exceptions and their bounded
diagnostic strings are outside that payload accounting.

The internal array-data demand separately emits referenced payload element bytes
with both instruction and payload PC, index and byte width. It never infers runtime
array type, signedness or reachability and is not part of public numeric queries.
Elements are counted once per instruction reference against the same payload and
validation-work limits, in addition to the existing payload structure check.

The internal switch-target demand emits one record for each referenced packed or
sparse switch case, in instruction and payload order. Each record retains switch
PC, payload PC, signed int32 key, case index and checked local destination PC;
shared payloads are emitted once per referring instruction because targets are
relative to that instruction. The existing validation and payload work charges
already count each target check; emitting records adds PMR allocations but no
additional logical work charge. This is not a default branch, reachability, CFG,
runtime behavior or public query/ABI guarantee. Failure returns no partial result.

Work is bounded by `max_code_units`, `max_instructions` and
`max_payload_elements` (each defaults to 1,048,576). The payload counter includes
declared payload elements and every switch target check, including repeated references
to a shared switch payload. This prevents one large shared payload from causing an
unbounded number of target checks. Cancellation is tested at each instruction and
at most every 1,024 iterated payload elements. Allocation failure is propagated for
the Engine/ABI boundary to classify.

This is not a complete ART method verifier. It does not establish target method
prototype word counts, runtime register types, method/type semantics, move-result or
move-exception placement, reachable fallthrough, exception handler instruction
boundaries, CFG correctness, dataflow or runtime dispatch. An enclosing integration
must retain these distinctions in its coverage/validation fields. Metadata validation
and instruction validation have separate prerequisites and results.

## Source facts and provenance

- AOSP bytecode format: <https://source.android.com/docs/core/runtime/dalvik-bytecode>
- AOSP DEX format: <https://source.android.com/docs/core/runtime/dex-format>
- Opcode metadata pin: `platform/art` commit
  `6484611fd45e69db9f33f98bfd6864014b030ecf`, file
  `libdexfile/dex/dex_instruction_list.h`, blob
  `bbd7abd8e52b31ac293b416f8527a439ea9b6bab`.
- Reference file notice: Copyright (C) 2011 The Android Open Source Project,
  Apache License 2.0. The implementation does not import or copy that source file.
  Numeric opcode/format facts were independently organized into the local decoder.
- `tests/fixtures/generated/instructions/opcode_widths.json` records all 256 factual
  opcode widths from that fixed source for independent audit. All 256 match the
  local width table; executable tests additionally exercise every standard opcode
  width and reject every reserved opcode.

The standalone tests construct real code-item byte sequences, rather than full APKs.
They are local decoder evidence and do not establish a complete DEX, APK or Android
runtime acceptance result. The initial Debug build needed an explicit `<string>`
include in the test translation unit; that build error was fixed before execution.
The current 354 behavior cases pass with MSVC AddressSanitizer and
`_ITERATOR_DEBUG_LEVEL=0`; the latter avoids MSVC debug-iterator proxy allocation
inside noexcept STL constructors and matches the Engine resource-failure test profile.

Internal `Demand::method_constants` emits the instruction PC, destination register,
local table index, opcode and distinct method-handle or method-type domain for
`const-method-handle` (0xfe) and `const-method-type` (0xff), available from DEX 039.
Each emitted fact costs one additional validation work unit; checked references,
registers, version, cancellation and PMR error paths remain authoritative. No
invocation, method resolution, runtime type or ART behavior is inferred. This
internal demand is not a QueryIR capability or a public ABI.
