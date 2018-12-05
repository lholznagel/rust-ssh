profile:
	cargo build
	valgrind --tool=massif target/debug/examples/server

server:
	cargo run --example server

ssh:
	ssh -vvv -o "UserKnownHostsFile /dev/null" -o "StrictHostKeyChecking=no" 0.0.0.0 -p 1337 -i ./resources/id_ed25519
