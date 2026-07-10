# sevra CLI — the neutral targets. Parity with db.md's Makefile ergonomics.
.PHONY: build release test lint fmt deny check clean

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --all

deny:
	cargo deny check

# The full pre-commit gate: format check, clippy, tests.
check: fmt lint test

clean:
	cargo clean
