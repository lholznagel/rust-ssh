# rssh

Rust ssh implementation.

Current WIP

## Run the example

`cargo run --example server` - Starts the example server

`ssh 0.0.0.0 -p 1337 -v -o "UserKnownHostsFile /dev/null" -o "StrictHostKeyChecking=no"` - Opens a ssh connection to the example server

## Run the example using the makefile

`make server` - Starts a example server

`make ssh` -  Opens a ssh connection to the example server
