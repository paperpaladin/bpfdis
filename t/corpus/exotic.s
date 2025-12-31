# Instructions clang will not emit from C, assembled by hand so that they
# appear inside a real ELF object and not only in the encoding sweep.
#
# Three of these are instructions LLVM's assembler writes and its own
# disassembler cannot read back: the 32-bit atomic fetch-or, exchange and
# compare-exchange. llvm-objdump prints <unknown> for all three. They are
# here deliberately, because an oracle's blind spot is worth having a
# fixture for.
	.text
	.globl exotic
	.type exotic, @function
exotic:
	r0 = *(u32 *)skb[4]
	r0 = *(u16 *)skb[r3]
	r0 = *(u8 *)skb[0]
	r0 = *(u32 *)skb[r1]
	may_goto +2
	gotol +1
	r1 = (s8)r2
	r1 = (s16)r2
	r1 = (s32)r2
	w1 = (s8)w2
	w1 = (s16)w2
	r1 = *(s8 *)(r2 + 4)
	r1 = *(s16 *)(r2 + 4)
	r1 = *(s32 *)(r2 - 8)
	r1 s/= r2
	r1 s%= r2
	w1 s/= w2
	w1 s%= w2
	r1 s/= 7
	w1 s%= 3
	r1 = bswap16 r1
	r1 = bswap32 r1
	r1 = bswap64 r1
	r1 = le16 r1
	r1 = le32 r1
	r1 = le64 r1
	r1 = be16 r1
	r1 = be32 r1
	r1 = be64 r1
	w2 = atomic_fetch_add((u32 *)(r1 + 0), w2)
	w2 = atomic_fetch_or((u32 *)(r1 + 0), w2)
	w2 = xchg32_32(r1 + 0, w2)
	w0 = cmpxchg32_32(r1 + 0, w0, w2)
	r2 = atomic_fetch_and((u64 *)(r1 + 8), r2)
	r2 = atomic_fetch_xor((u64 *)(r1 + 8), r2)
	r2 = xchg_64(r1 - 8, r2)
	r0 = cmpxchg_64(r1 + 0, r0, r2)
	lock *(u32 *)(r1 + 0) += w2
	lock *(u64 *)(r1 + 0) |= r2
	lock *(u64 *)(r1 + 0) &= r2
	lock *(u64 *)(r1 + 0) ^= r2
	r1 = addr_space_cast(r2, 1, 0)
	r1 = addr_space_cast(r2, 0, 1)
	r1 = -r1
	w1 = -w1
	r1 <<= 63
	w1 s>>= 31
	*(u64 *)(r10 - 256) = 0
	r1 = *(u64 *)(r10 - 256)
	callx r3
	exit
	.size exotic, .-exotic
