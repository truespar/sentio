# syntax=docker/dockerfile:1.7

# ── Builder ──────────────────────────────────────────────────────────────
FROM rust:1-bookworm AS builder

WORKDIR /build

# aws-lc-rs (rustls backend) needs cmake + a C toolchain; build-essential is
# already present in the rust: image. libclang is only needed by some crates
# in the tree - install here rather than debugging a rebuild later.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake \
        libclang-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Use the committed .sqlx/ offline cache so the build doesn't need a live DB.
ENV SQLX_OFFLINE=true

RUN cargo build --release --bin sentio-smtp \
    && strip target/release/sentio-smtp

# ── Runtime ──────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libcap2-bin \
        tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 sentio \
    && useradd  --system --uid 1000 --gid sentio \
                --home-dir /var/lib/sentio --shell /usr/sbin/nologin sentio \
    && mkdir -p /etc/sentio /var/lib/sentio \
    && chown -R sentio:sentio /etc/sentio /var/lib/sentio

COPY --from=builder /build/target/release/sentio-smtp /usr/local/bin/sentio-smtp
COPY --from=builder /build/migrations /usr/share/sentio/migrations
COPY config/oss.toml /etc/sentio/oss.toml

# Allow the non-root user to bind :25/465/587 without full root.
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/sentio-smtp

USER sentio
WORKDIR /var/lib/sentio

EXPOSE 25 465 587 8080 9090

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 \
    CMD curl -fsS http://localhost:8080/health/ready || exit 1

ENTRYPOINT ["/usr/local/bin/sentio-smtp"]
CMD ["--config", "/etc/sentio/oss.toml", "serve"]
