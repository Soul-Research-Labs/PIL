# ── Build stage ──────────────────────────────────────────
FROM rust:1.80-bookworm AS builder

WORKDIR /build

# Cache dependency builds: copy manifests first
COPY Cargo.toml Cargo.lock ./
COPY crates/pil-primitives/Cargo.toml crates/pil-primitives/
COPY crates/pil-note/Cargo.toml crates/pil-note/
COPY crates/pil-tree/Cargo.toml crates/pil-tree/
COPY crates/pil-circuits/Cargo.toml crates/pil-circuits/
COPY crates/pil-prover/Cargo.toml crates/pil-prover/
COPY crates/pil-verifier/Cargo.toml crates/pil-verifier/
COPY crates/pil-pool/Cargo.toml crates/pil-pool/
COPY crates/pil-node/Cargo.toml crates/pil-node/
COPY crates/pil-client/Cargo.toml crates/pil-client/
COPY crates/pil-sdk/Cargo.toml crates/pil-sdk/
COPY crates/pil-rpc/Cargo.toml crates/pil-rpc/
COPY crates/pil-cli/Cargo.toml crates/pil-cli/
COPY crates/pil-cardano/Cargo.toml crates/pil-cardano/
COPY crates/pil-cosmos/Cargo.toml crates/pil-cosmos/
COPY crates/pil-bridge/Cargo.toml crates/pil-bridge/
COPY crates/pil-groth16-wrapper/Cargo.toml crates/pil-groth16-wrapper/
COPY crates/pil-hydra/Cargo.toml crates/pil-hydra/
COPY crates/pil-integration-tests/Cargo.toml crates/pil-integration-tests/
COPY crates/pil-benchmarks/Cargo.toml crates/pil-benchmarks/

# Create stub lib.rs for each crate so cargo can resolve deps
RUN for d in crates/*/; do mkdir -p "$d/src" && echo "" > "$d/src/lib.rs"; done
# CLI crate needs a main.rs
RUN mkdir -p crates/pil-cli/src && echo "fn main() {}" > crates/pil-cli/src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release --workspace 2>/dev/null || true

# Copy real source code
COPY crates/ crates/

# Build the actual binaries
RUN cargo build --release --bin pil-cli

# ── Runtime stage ────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash pil

COPY --from=builder /build/target/release/pil-cli /usr/local/bin/pil

USER pil
WORKDIR /home/pil

EXPOSE 8080

ENTRYPOINT ["pil"]
CMD ["serve", "--bind", "0.0.0.0:8080"]
