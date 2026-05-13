######## Proto ########

IBC_GO_PATH ?= $$HOME/go/src/github.com/cosmos/ibc-go
ETHEREUM_LIGHT_CLIENT_TYPES_PATH ?= $$HOME/go/src/github.com/datachainlab/ethereum-light-client-types

.PHONY: proto
proto:
	cd proto-compiler && cargo run -- compile -i $(IBC_GO_PATH) -e $(ETHEREUM_LIGHT_CLIENT_TYPES_PATH) -o ../proto/src/prost

######## Build ########

.PHONY: sync-lock
sync-lock:
	cargo update -p kona-client
	cd tools/deps && python sync_lock.py
	# Check build
	cargo build

######## Lint ########

.PHONY: lint-tools
lint-tools:
	rustup component add rustfmt clippy
	cargo +nightly install cargo-machete

.PHONY: fmt
fmt:
	@cargo fmt --all $(CARGO_FMT_OPT)

.PHONY: lint
lint:
	@$(MAKE) CARGO_FMT_OPT=--check fmt
	@cargo clippy --locked --tests -- -D warnings
	@cargo machete
