# Multi-mode build for auth-service.
#
#   BUILD_MODE=local (default) — full Rust build inside Docker. Used by
#       `make docker-build-local` and any one-shot `docker build` without
#       a pre-compiled binary on disk.
#   BUILD_MODE=ci — expects the binary pre-staged at `dist/auth-service`
#       in the build context (CI cross-compiles natively, avoids QEMU).
#
# Select with `docker build --build-arg BUILD_MODE={local|ci} …`. BuildKit
# prunes unreferenced stages, so the Rust toolchain is never pulled in CI
# mode, and `dist/` is never required in local mode.

ARG BUILD_MODE=local

# ---- builder ----------------------------------------------------------
# Reached only when BUILD_MODE=local.
FROM rust:1.95.0-slim-trixie@sha256:e14e87345b4d5964ddcc3491d27ee046a0f23820f340c3c1e24da6880141f7c0 AS builder
WORKDIR /app

# Cache dependency compilation by building a stub crate first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
 && echo 'fn main(){}' > src/main.rs \
 && cargo build --release \
 && rm -rf src

# Real sources + final build.
COPY src ./src
RUN touch src/main.rs \
 && cargo build --release


# ---- source selector --------------------------------------------------
# Two stages with identical interfaces (a single /auth-service file). The
# `source` alias picks one based on BUILD_MODE.
FROM scratch AS local-source
COPY --from=builder /app/target/release/auth-service /auth-service

FROM scratch AS ci-source
COPY dist/auth-service /auth-service

FROM ${BUILD_MODE}-source AS source


# ---- runtime ----------------------------------------------------------
FROM gcr.io/distroless/cc:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2
COPY --from=source /auth-service /auth-service
USER nonroot:nonroot
EXPOSE 50051 9090
ENTRYPOINT ["/auth-service"]
