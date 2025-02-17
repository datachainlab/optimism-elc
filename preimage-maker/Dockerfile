FROM rust:1.81 as builder

WORKDIR /app
RUN apt-get update && apt-get install -y \
    clang \
    libclang-dev \
    cmake \
    build-essential \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY rust-toolchain .
RUN rustup install $(cat rust-toolchain)
RUN rustup default $(cat rust-toolchain)

COPY Cargo.* .
COPY elc elc/
COPY preimage-maker preimage-maker/
RUN cargo build --release --manifest-path preimage-maker/Cargo.toml

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/optimism-preimage-maker /usr/local/bin/optimism-preimage-maker
CMD ["optimism-preimage-maker", "--l2", "http://host.docker.internal:9545","--l1", "http://host.docker.internal:8545","--beacon", "http://host.docker.internal:5052","--rollup", "http://host.docker.internal:7545"]