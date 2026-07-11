# A legacy map definition with less section behind it than the struct needs.
#
# The symbol says 20 bytes, which is the size of a struct bpf_map_def, and
# the section holds 12. A reader with a five-word buffer fills three of them
# from the file and reports the other two as whatever the buffer was
# initialised to, which is zero, and a zero max_entries looks exactly like a
# map someone declared that way.
#
# This is METHOD's oversized-buffer rule in the only form Rust leaves open:
# nothing is uninitialised and nothing crashes, so the padding is invisible
# unless the reader counts what it actually read. The suite requires the
# note naming 3 of 5 words, which is the only thing that separates this from
# a map record made half of file and half of buffer.
	.section maps,"aw",@progbits
	.globl shortmap
	.type shortmap, @object
	.size shortmap, 20
shortmap:
	.long 1
	.long 4
	.long 8
