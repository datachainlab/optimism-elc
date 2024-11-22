# proto-compiler

```
cargo run compile --ibc <ibc-go-path> --out ../proto/src/prost
rm ../proto/src/prost/ibc.lightclients.ethereum.v1.rs
rm ../proto/src/prost/google.protobuf.rs
```

<ibc-go-path> is repository of [cosmos/ibc-go](https://github.com/cosmos/ibc-go)
