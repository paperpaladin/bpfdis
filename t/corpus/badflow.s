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
