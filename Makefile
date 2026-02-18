# Default target builds; `make test` runs the suite. Keep `all` first:
# the collection's build gate builds the DEFAULT target of every commit.
CARGO ?= cargo

all:
	$(CARGO) build --release --offline

test: all overread
	sh t/run.sh

# The Rust form of METHOD's oversized-buffer rule.
#
# A sanitizer is not the instrument here: Rust bounds-checks every index, so
# an off-by-one is a panic rather than a wild read. What it is NOT is a
# panic when the buffer is bigger than the data it describes, and this build
# plants exactly that read. With `slot_map` sized to the number of slots the
# planted index aborts; with one spare element it returns None and the
# program produces a wrong answer in silence.
#
# 134 is SIGABRT through the shell, and `panic = "abort"` is what makes a
# panic reach it. bpfdis itself only ever exits 0, 1, 2 or 3, so a report
# cannot be confused with a clean refusal or a usage error.
overread:
	@RUSTFLAGS='--cfg bpfdis_plant_overread' $(CARGO) build --release --offline \
		--target-dir target/overread >/dev/null 2>&1 || \
		{ echo "[overread] build failed"; exit 1; }
	@clang -target bpf -mcpu=v3 -O2 -c t/corpus/basic.c -o target/overread/probe.o
	@set +e; \
	 target/overread/release/bpfdis -d target/overread/probe.o >/dev/null 2>&1; \
	 rc=$$?; \
	 if [ $$rc -eq 134 ]; then \
		echo "[overread] the planted read past the end of slot_map aborts"; \
	 else \
		echo "[overread] FAIL: planted over-read exited $$rc, expected 134"; \
		exit 1; \
	 fi

clean:
	$(CARGO) clean
	rm -rf t/scratch t/corpus/*.o target/overread

.PHONY: all test clean overread
