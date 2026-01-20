# A stack access through a register that is not r10.
#
# This fixture exists because two mutations survived everything else. Every
# dereference in the compiled corpus uses r10 directly, so dropping the base
# register's own frame offset from the depth calculation changes nothing,
# and so does letting a 32-bit move carry the frame-pointer fact. clang will
# not emit either shape: it folds a constant stack offset into the access.
#
# There is no oracle for this one. clang's -bpf-stack-size accounting is
# done at frame-index elimination and never sees a hand-written derived
# base, and the kernel verifier is out of reach. The expected numbers below
# are read off the three instructions that produce them, and t/run.sh
# asserts them as such, labelled.
#
# derived:  r2 = r10 - 8, then a store at r2 - 24, so the lowest byte
#           touched is r10 - 32 and the frame is 32 bytes. A tool that
#           ignores the base reports 24; one that ignores the access
#           reports 8.
	.text
	.globl derived
	.type derived, @function
derived:
	r2 = r10
	r2 += -8
	*(u64 *)(r2 - 24) = r1
	r0 = *(u64 *)(r2 - 24)
	exit
	.size derived, .-derived

# truncated: a 32-bit move of the frame pointer keeps only its low half, so
# the result is not a stack address at all and the store through it is not a
# stack access. Expected depth 0. A tool that lets w-moves carry the fact
# reports 16. The store has to be the very next instruction: a 32-bit ADD
# after it would drop the fact for a different reason and the mutation
# would survive again, which is what the first version of this fixture
# did.
	.globl truncated
	.type truncated, @function
truncated:
	w3 = w10
	*(u64 *)(r3 - 16) = r1
	r0 = 0
	exit
	.size truncated, .-truncated
