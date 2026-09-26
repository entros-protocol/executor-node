# BuildKit invalidates the binary when copied source files change.
FROM rust:1.91.0-bookworm@sha256:e187887ec511b3d93e45c0231d2f0fd59f1347526c58aa86343aa83c74f3e1a9 AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --locked --release

# The runtime needs CA certificates and OpenSSL for outbound HTTPS.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

RUN apt-get update \
    && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home entros

COPY --from=builder /app/target/release/executor-node /usr/local/bin/executor-node

USER entros

# The service reads PORT first and uses LISTEN_ADDR for local development.
EXPOSE 8080

CMD ["executor-node"]
