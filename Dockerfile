# syntax=docker/dockerfile:1

FROM rust:1.99.1-slim-trixie AS build
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates git pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --locked --release --bin ifcx-oci \
    && install -D target/release/ifcx-oci /out/ifcx-oci \
    && install -d -m 0700 -o 65532 -g 65532 /out/data

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /out/ifcx-oci /usr/local/bin/ifcx-oci
COPY --from=build --chown=65532:65532 /out/data /data
COPY LICENSE /usr/share/licenses/ifcx-oci/LICENSE
USER 65532:65532
WORKDIR /data
VOLUME ["/data"]
EXPOSE 5000
ENTRYPOINT ["/usr/local/bin/ifcx-oci"]
CMD ["serve", "--data", "/data", "--listen", "0.0.0.0:5000"]
