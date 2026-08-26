# Programs with the defects the verifier rejects, one per function.
#
# There is no outside authority for these. The kernel verifier is the only
# thing that can say "this would be rejected" and it is unreachable here;
# see t/verifier_probe.c and the README. clang assembles all of them
# without complaint, libbpf opens the object, and llvm-objdump disassembles
# it, so no installed tool has an opinion. What these fixtures buy is that
# every finding bpfdis can report is reached by something, and that a
# mutation disabling one of them has a test to kill.
#
# Each one gets its own section so that it is an ENTRY program rather than
# a subprogram. The difference is not cosmetic: a subprogram is called with
# up to five arguments, so r1 through r5 arrive live, and the first version
# of the uninitialised-register fixture read r3 inside .text and was
# correctly found clean.

# A jump that lands on the second half of a 16-byte immediate load. The
# load occupies slots 2 and 3; `goto +1` at slot 1 targets slot 3.
	.section socket/midwide,"ax",@progbits
	.globl midwide
	.type midwide, @function
midwide:
	r0 = 0
	goto +1
	r1 = 0x1122334455667788 ll
	exit
	.size midwide, .-midwide

# Code nothing can reach: the store at slot 2 sits between an unconditional
# jump and its target.
	.section socket/unreach,"ax",@progbits
	.globl unreach
	.type unreach, @function
unreach:
	r0 = 0
	goto +1
	r0 = 1
	exit
	.size unreach, .-unreach

# A jump past the end of its own function.
	.section socket/outside,"ax",@progbits
	.globl outside
	.type outside, @function
outside:
	r0 = 0
	goto +100
	exit
	.size outside, .-outside

# Reads r3, which nothing has written, and then r6, which is callee-saved
# and so is not live even in a subprogram. r1 is the context pointer and is
# the only general register live on entry to a program.
	.section socket/uninit,"ax",@progbits
	.globl uninit
	.type uninit, @function
uninit:
	r0 = r3
	r0 += r6
	exit
	.size uninit, .-uninit

# A self-loop with no way out, and an exit nothing reaches.
	.section socket/spin,"ax",@progbits
	.globl spin
	.type spin, @function
spin:
	r0 = 0
	goto -1
	exit
	.size spin, .-spin

# Runs off the end of the section with no exit instruction.
	.section socket/runoff,"ax",@progbits
	.globl runoff
	.type runoff, @function
runoff:
	r0 = 0
	r1 = 1
	.size runoff, .-runoff

# A subprogram call to a slot that is not the first instruction of any
# function. The verifier only lets BPF_PSEUDO_CALL enter a subprogram at
# its entry point.
#
# Written as bytes because llvm-mc has no syntax for it: `call 2` assembles
# to src_reg 0, which is helper 2, and the assembler offers no way to set
# the source register. That is the same hole the disassembly allow-list
# exists for, seen from the writing end. The encoding below is
# 85 10 00 00 02 00 00 00, a call with src_reg 1 and imm 2, so the target
# is slot 0 + 1 + 2 = 3, one past the last instruction of a 3-slot section.
	.section socket/badcall,"ax",@progbits
	.globl badcall
	.type badcall, @function
badcall:
	.long 0x00001085
	.long 0x00000002
	r0 = 0
	exit
	.size badcall, .-badcall

# Direct recursion. The verifier has no stack to unwind and rejects a cycle
# in the subprogram call graph outright, so a function that calls itself is
# a rejection however well behaved it otherwise is.
#
# Bytes again, for the reason above: llvm-mc cannot write a call with
# src_reg 1. 85 10 00 00 ff ff ff ff is a call with imm -1, so the target is
# slot 0 + 1 - 1 = 0, which is this function's own entry.
	.section socket/selfcall,"ax",@progbits
	.globl selfcall
	.type selfcall, @function
selfcall:
	.long 0x00001085
	.long 0xffffffff
	r0 = 0
	exit
	.size selfcall, .-selfcall

# Nine subprogram frames, one more than the verifier allows.
#
# d0 calls d1 calls d2 ... calls d8, each in the same section so every call
# resolves without a relocation and the graph can be walked. The verifier's
# limit is MAX_CALL_FRAMES, which is 8, and it is written down in src/cfg.rs
# from the kernel source rather than measured, because the verifier that
# would settle it is unreachable here.
#
# Each of d0..d7 is `call pc+1` then `exit`: 85 10 00 00 01 00 00 00 puts the
# target two slots on, which is the next function's entry.
	.section socket/deepcall,"ax",@progbits
	.globl d0
	.type d0, @function
d0:
	.long 0x00001085
	.long 0x00000001
	exit
	.size d0, .-d0
	.globl d1
	.type d1, @function
d1:
	.long 0x00001085
	.long 0x00000001
	exit
	.size d1, .-d1
	.globl d2
	.type d2, @function
d2:
	.long 0x00001085
	.long 0x00000001
	exit
	.size d2, .-d2
	.globl d3
	.type d3, @function
d3:
	.long 0x00001085
	.long 0x00000001
	exit
	.size d3, .-d3
	.globl d4
	.type d4, @function
d4:
	.long 0x00001085
	.long 0x00000001
	exit
	.size d4, .-d4
	.globl d5
	.type d5, @function
d5:
	.long 0x00001085
	.long 0x00000001
	exit
	.size d5, .-d5
	.globl d6
	.type d6, @function
d6:
	.long 0x00001085
	.long 0x00000001
	exit
	.size d6, .-d6
	.globl d7
	.type d7, @function
d7:
	.long 0x00001085
	.long 0x00000001
	exit
	.size d7, .-d7
	.globl d8
	.type d8, @function
d8:
	r0 = 0
	exit
	.size d8, .-d8
