# optimism-elc

## Integration Test

```
make chain
cargo build --release --manifest-path preimage-maker/Cargo.toml
cargo test --manifest-path preimage-maker/Cargo.toml --test e2e
cargo test --manifest-path elc/light-client/Cargo.toml --lib oracle
```