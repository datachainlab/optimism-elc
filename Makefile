.PHONY: chain
chain:
	git clone --depth 1 -b v1.10.0 https://github.com/ethereum-optimism/optimism ./chain
	sed 's/v5.2.1/v6.0.1/g' chain/ops-bedrock/l1-lighthouse.Dockerfile > chain/ops-bedrock/l1-lighthouse.Dockerfile.tmp
	mv chain/ops-bedrock/l1-lighthouse.Dockerfile.tmp chain/ops-bedrock/l1-lighthouse.Dockerfile
	sed 's/port=9000/port=9000 --light-client-server/g' chain/ops-bedrock/l1-lighthouse-bn-entrypoint.sh > chain/ops-bedrock/l1-lighthouse-bn-entrypoint.sh.tmp
	mv chain/ops-bedrock/l1-lighthouse-bn-entrypoint.sh.tmp chain/ops-bedrock/l1-lighthouse-bn-entrypoint.sh

.PHONY: devnet-up
devnet-up:
	make -C chain devnet-up

.PHONY: devnet-down
devnet-down:
	make -C chain devnet-down

.PHONY: devnet-clean
devnet-clean:
	make -C chain devnet-clean

.PHONY: status
status:
	curl -X POST localhost:7545 -d '{"method":"optimism_syncStatus", "jsonrpc": "2.0", "id":1, "params":[]}' -H "Content-Type: application/json" | jq .result.finalized_l2


