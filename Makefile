profile:
	cargo build
	valgrind --tool=massif target/debug/examples/server
