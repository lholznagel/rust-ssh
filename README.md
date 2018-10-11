# Rust-ssh-transport-protocol

Implements the ssh transport layer defined by the [RFC 4253](https://tools.ietf.org/html/rfc4253.html)

Current WIP

## Run the example

`cargo run --example server` - Starts the example server

`ssh 0.0.0.0 -p 1337 -v` - Opens a ssh connection to the example server

## Run the example using the makefile

`make server` - Starts a example server

`make ssh` -  Opens a ssh connection to the example server
