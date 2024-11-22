# proto-compiler

```
cargo run compile --ibc <ibc-go-path> --out ../proto/src/prost
rm ../proto/src/prost/ibc.lightclients.ethereum.v1.rs
rm ../proto/src/prost/google.*.rs
rm ../proto/src/prost/ibc.core.*.rs
rm ../proto/src/prost/cosmos.*.rs
```

<ibc-go-path> is repository of [cosmos/ibc-go](https://github.com/cosmos/ibc-go)
