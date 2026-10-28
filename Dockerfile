# syntax=docker/dockerfile:1
#
# netnode container image: a single static binary on an empty (`scratch`) base.
# Final image size is about 3 MB.
#
# Build:  docker build -t netnode .
# Run:    docker run --rm -it --network host --cap-add NET_RAW --cap-add NET_ADMIN netnode --iface eth1
#
# `--network host` is required: netnode must see the host's real eth1, not the
# container's virtual interface.

# ---- build stage: compile against musl so the binary has no runtime dependencies
ARG RUST_IMAGE=rust:1-alpine
FROM ${RUST_IMAGE} AS build
RUN apk add --no-cache musl-dev
WORKDIR /src

# Build dependencies first, so editing src/ does not re-download or re-compile them.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

# ---- runtime stage: nothing but the binary
FROM scratch
COPY --from=build /src/target/release/netnode /netnode
# Mount a directory here to load or save host tables: -v "$PWD:/data"
WORKDIR /data
ENTRYPOINT ["/netnode"]
CMD ["--iface", "eth1"]
