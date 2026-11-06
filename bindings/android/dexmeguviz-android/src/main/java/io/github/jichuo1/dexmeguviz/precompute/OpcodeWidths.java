package io.github.jichuo1.dexmeguviz.precompute;

// Factual opcode widths from the existing pinned project table (SHA-256 7eaa06d9...822c7).
// AOSP reference: 6484611fd45e69db9f33f98bfd6864014b030ecf/dex_instruction_list.h.
final class OpcodeWidths {
    private static final int[] WIDTHS={1,1,2,3,1,2,3,1,2,3,1,1,1,1,1,1,1,1,1,2,3,2,2,3,5,2,2,3,2,1,1,2,2,1,2,2,3,3,3,1,1,2,3,3,3,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,0,0,0,0,0,0,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,3,3,3,3,3,0,3,3,3,3,3,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,4,3,3,2,2};
    static int width(int opcode){return WIDTHS[opcode];}
    private OpcodeWidths(){}
}
