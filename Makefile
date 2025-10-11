# Default target builds; `make test` runs the suite. Keep `all` first:
# the collection's build gate builds the DEFAULT target of every commit.
CARGO ?= cargo

all:
	$(CARGO) build --release --offline

test: all
	sh t/run.sh

clean:
	$(CARGO) clean
	rm -rf t/scratch t/corpus/*.o

.PHONY: all test clean
