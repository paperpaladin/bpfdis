# A section whose last function does not reach the end of it.
#
# Every function in a compiler-generated object runs to the section end or to
# the next function, so a reader that ignores st_size entirely gets the same
# answer as one that uses it, and a mutation deleting the size handling
# survives the whole corpus. This fixture is the one shape that separates
# them: `small` is two instructions, the section is six slots, and the four
# slots after it belong to no function.
#
# Those four slots are a 16-byte wide load followed by two words of zero,
# which decode as an unallocated opcode. Both llvm-objdump and bpfdis refuse
# the zeros, which exercises the refusal path inside a real object.
	.text
	.globl small
	.type small, @function
small:
	r0 = 0
	exit
	.size small, .-small
	.long 0x00000018
	.long 0x00000001
	.long 0x00000000
	.long 0x00000002
	.long 0x00000000
	.long 0x00000000
	.long 0x00000000
	.long 0x00000000
