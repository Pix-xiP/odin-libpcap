package odin_libpcap

import _c "core:c"

when ODIN_OS == .Windows {
	// WinPcap, NPcap are the options here.
	foreign import bpf "system:npcap" // 99% sure this is wrong, but placeholder
}
when ODIN_OS == .Linux {
	foreign import bpf "pcap"
}
when ODIN_OS == .Darwin {
	// HACK: Ran into issues with it finding the dylib, so moved it into the folder..
	foreign import bpf "system:pcap"
}

BPF_RELEASE :: 199606 // BSD style release dat.

when ODIN_OS == .Windows {
	bpf_int32 :: _c.long
	bpf_u_int32 :: _c.ulong
} else {
	bpf_int32 :: _c.int
	bpf_u_int32 :: _c.uint
}

BPF_ALIGNMENT :: size_of(i64) // Double check could be long 32.

// for NETBSD use size of bpf_int32
BPF_WORDALIGN :: proc(x: uint) { 	// MACRO - May want to take another look
	var := ((x) + BPF_ALIGNMENT - 1) &~ (BPF_ALIGNMENT - 1)
	// I THINK this is just rounding to the next multiple of sizeof(lone)
	// Might work on both memory addresses and data sizes?
}

bpf_program :: struct {
	bf_len:   _c.uint,
	bf_insns: ^bpf_insn,
}

// Instruction Data Structure.
bpf_insn :: struct {
	code: _c.ushort,
	jt:   _c.uchar,
	jf:   _c.uchar,
	k:    bpf_u_int32,
}

@(default_calling_convention = "c", link_prefix = "bpf_")
foreign bpf {
	filter :: proc(pc: ^bpf_insn, pkt: [^]byte, wirelen: _c.uint32_t, buflen: _c.uint32_t) -> _c.uint32_t ---

	validate :: proc(fcode: ^bpf_insn, flen: _c.int) -> _c.int ---

	image :: proc(pc: ^bpf_insn, arg: _c.int) -> cstring ---
	// Needs to be tagged cause clash with pcap_dump. 
	_dump :: proc(p: ^bpf_program, arg: _c.int) ---
}

// The upper 8 bits of the opcode aren't used. BSD/OS used 0x8000.

// instruction classes
// #define BPF_CLA ::SS(code) ((code) & 0x07)
BPF_CLASS :: proc(code: uint) -> uint {
	return (code) & 0x07
}

BPF_LD :: 0x00
BPF_LDX :: 0x01
BPF_ST :: 0x02
BPF_STX :: 0x03
BPF_ALU :: 0x04
BPF_JMP :: 0x05
BPF_RET :: 0x06
BPF_MISC :: 0x07

// ld/ldx fields 
// #define BPF_SIZ ::E(code)	((code) & 0x18)
BPF_W :: 0x00
BPF_H :: 0x08
BPF_B :: 0x10
//				0x18	reserved; used by BSD/OS 
// #define BPF_MOD ::E(code)	((code) & 0xe0)
BPF_IMM :: 0x00
BPF_ABS :: 0x20
BPF_IND :: 0x40
BPF_MEM :: 0x60
BPF_LEN :: 0x80
BPF_MSH :: 0xa0
//				0xc0	reserved; used by BSD/OS 
//				0xe0	reserved; used by BSD/OS 

// alu/jmp fields 
// #define BPF_OP( ::code)	((code) & 0xf0)
BPF_ADD :: 0x00
BPF_SUB :: 0x10
BPF_MUL :: 0x20
BPF_DIV :: 0x30
BPF_OR :: 0x40
BPF_AND :: 0x50
BPF_LSH :: 0x60
BPF_RSH :: 0x70
BPF_NEG :: 0x80
BPF_MOD :: 0x90
BPF_XOR :: 0xa0
//				0xb0	reserved 
//				0xc0	reserved 
//				0xd0	reserved 
//				0xe0	reserved 
//				0xf0	reserved 

BPF_JA :: 0x00
BPF_JEQ :: 0x10
BPF_JGT :: 0x20
BPF_JGE :: 0x30
BPF_JSET :: 0x40
//				0x50	reserved; used on BSD/OS 
//				0x60	reserved 
//				0x70	reserved 
//				0x80	reserved 
//				0x90	reserved 
//				0xa0	reserved 
//				0xb0	reserved 
//				0xc0	reserved 
//				0xd0	reserved 
//				0xe0	reserved 
//				0xf0	reserved 
// #define BPF_SRC ::(code)	((code) & 0x08)
BPF_K :: 0x00
BPF_X :: 0x08

// ret - BPF_K a ::nd BPF_X a ::lso apply 
// #define BPF_RVA ::L(code)	((code) & 0x18)
BPF_A :: 0x10
//				0x18	reserved 

// misc 
// #define BPF_MIS ::COP(code) ((code) & 0xf8)
BPF_TAX :: 0x00
//				0x08	reserved 
//				0x10	reserved 
//				0x18	reserved 
// #define	BPF_COP ::		0x20	NetBSD "coprocessor" extensions 
//				0x28	reserved 
//				0x30	reserved 
//				0x38	reserved 
// #define	BPF_COP ::X	0x40	NetBSD "coprocessor" extensions 
//					also used on BSD/OS 
//				0x48	reserved 
//				0x50	reserved 
//				0x58	reserved 
//				0x60	reserved 
//				0x68	reserved 
//				0x70	reserved 
//				0x78	reserved 
BPF_TXA :: 0x80
//				0x88	reserved 
//				0x90	reserved 
//				0x98	reserved 
//				0xa0	reserved 
//				0xa8	reserved 
//				0xb0	reserved 
//				0xb8	reserved 
//				0xc0	reserved; used on BSD/OS 
//				0xc8	reserved 
//				0xd0	reserved 
//				0xd8	reserved 
//				0xe0	reserved 
//				0xe8	reserved 
//				0xf0	reserved 
//				0xf8	reserved 
