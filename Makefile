.PHONY: test
test:
	cargo test

.PHONY: cov
cov:
	cargo clean && \
	mkdir -p ./target/coverage/html && \
	CARGO_INCREMENTAL=0 \
	RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Cpanic=abort -Zpanic_abort_tests" \
	cargo test && \
	grcov . --binary-path ./target/debug/deps/ -s . -t html --ignore-not-existing --ignore '../*' --ignore "/*" -o target/coverage/html 
	
