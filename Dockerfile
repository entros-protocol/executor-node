# BuildKit invalidates the binary when copied source files change.
FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --locked --release

# The runtime needs CA certificates and OpenSSL for outbound HTTPS.
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

RUN apt-get update \
    && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home iam

COPY --from=builder /app/target/release/executor-node /usr/local/bin/executor-node

USER iam

# The service reads PORT first and uses LISTEN_ADDR for local development.
EXPOSE 8080

CMD ["executor-node"]
