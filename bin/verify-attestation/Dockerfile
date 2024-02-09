FROM docker.io/rust:1-bullseye AS buildtee
RUN curl -fsSLo /usr/share/keyrings/intel.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" > /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        rsync \
        pkg-config \
        libssl-dev \
        libcurl4-openssl-dev \
        libprotobuf-dev \
        protobuf-compiler \
        clang \
        libsgx-headers \
        libsgx-dcap-quote-verify-dev

WORKDIR /opt/vault/plugins

WORKDIR /build
RUN --mount=type=bind,target=/data rsync --exclude='/.git' --filter="dir-merge,- .gitignore" --exclude "Dockerfile-*" --exclude 'tee-vault-admin.manifest.template' -av /data/ ./
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=target \
    RUSTFLAGS="-C target-cpu=icelake-server --cfg mio_unsupported_force_waker_pipe" \
    cargo build --locked --target x86_64-unknown-linux-gnu --release -p verify-attestation --bin verify-attestation \
    && mv ./target/x86_64-unknown-linux-gnu/release/verify-attestation ./

FROM docker.io/ubuntu:20.04

RUN apt-get update \
    && apt-get install -y curl

RUN curl -fsSLo /usr/share/keyrings/intel.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" > /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        libsgx-dcap-default-qpl \
        libsgx-urts \
        libsgx-enclave-common \
        libsgx-dcap-quote-verify
RUN apt purge -y libsgx-ae-qve
RUN rm -rf /var/lib/apt/lists/*

COPY --from=buildtee /build/verify-attestation /bin/verify-attestation

ENTRYPOINT ["/bin/sh", "-c"]
CMD [ "verify-attestation" ]
