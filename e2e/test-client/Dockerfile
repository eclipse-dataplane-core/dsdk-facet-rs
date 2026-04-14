# Multi-stage Dockerfile for vault-test using cargo-chef for cached builds
# Build from project root: docker build --platform linux/amd64 -f e2e/test-client/Dockerfile -t vault-test:local .

FROM rust:bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /build

# Planner stage - analyze dependencies
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY siglet ./siglet
COPY e2e ./e2e
RUN cargo chef prepare --recipe-path recipe.json

# Builder stage - build dependencies then app
FROM chef AS builder

# Install build dependencies
RUN apt-get update && \
    apt-get install -y cmake && \
    rm -rf /var/lib/apt/lists/*

# Copy dependency recipe and build (this layer is cached)
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source code and build application (only this layer rebuilds on code changes)
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY siglet ./siglet
COPY e2e ./e2e
RUN cargo build --release --bin vault-test --package vault-e2e-test-client

# Runtime stage - minimal image
FROM debian:bookworm-slim

# Copy binary from builder
COPY --from=builder /build/target/release/vault-test /usr/local/bin/vault-test

RUN chmod +x /usr/local/bin/vault-test

ENTRYPOINT ["/usr/local/bin/vault-test"]
