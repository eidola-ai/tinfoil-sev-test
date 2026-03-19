FROM rust:1-slim@sha256:dc01d574f1afe9a97d3441e6f33a7fbd7443c7f257c185a901690276c94a778f AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
ENV CARGO_INCREMENTAL=0
ENV RUSTFLAGS="--remap-path-prefix /src=/"
RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:8af0e5095f9964007f5ebd11191dfe52dcb51bf3afa2c07f055fc5451b78ba0e
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/sev-probe /usr/local/bin/
EXPOSE 8080
CMD ["sev-probe"]
