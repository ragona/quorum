.PHONY: test
test:
	cargo test

.PHONY: cov
cov:
	cargo tarpaulin --out lcov --output-dir coverage/ && \
		rm *.profraw

