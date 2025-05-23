# optimism-elc

[![test](https://github.com/datachainlab/optimism-elc/actions/workflows/ci.yaml/badge.svg)](https://github.com/datachainlab/optimism-elc/actions/workflows/ci.yaml)

[ELC](https://docs.lcp.network/protocol/elc) implementation for [Optimism](https://github.com/ethereum-optimism/optimism).

NOTE: This project is currently under heavy development. Features may change or break.

## Supported Versions
- [lcp v0.2.14](https://github.com/datachainlab/lcp/releases/tag/v0.2.14)
- [optimism v1.13.1](https://github.com/ethereum-optimism/optimism/tree/v1.13.1)

## Related project

- [optimism-preimage-maker](https://github.com/datachainlab/optimism-preimage-maker): A tool to create preimages for Optimism ELC.
- [optimism-ibc-relay-prover](https://github.com/datachainlab/optimism-ibc-relay-prover): A tool to prove IBC packets on Optimism ELC.

## Integration with LCP
LCP requires a special configuration to run ELC due to the huge data size of preimage.
The following configurations are required:
* Enclave `StackMaxSize` and `HeapMaxSize` should be greater than `2GB`.
* Use client streaming RPC for `update_client`