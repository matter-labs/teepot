# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs

FROM teepot-self-attestation-test-sgx-dcap:base

WORKDIR /app

COPY packages/container-vault-sgx-azure/test-enclave-key.pem /tmp/
COPY assets/sgx_default_qcnl.conf.json /etc/sgx_default_qcnl.conf

RUN set -eux; \
    touch -r /nix/store /etc/sgx_default_qcnl.conf; \
    gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu \
      -Dentrypoint=$(readlink /bin/tee-self-attestation-test) \
      -Dexecdir=/bin \
      -Dlog_level=error \
      tee-self-attestation-test.manifest.toml tee-self-attestation-test.manifest; \
    gramine-sgx-sign --manifest tee-self-attestation-test.manifest --output tee-self-attestation-test.manifest.sgx --key /tmp/test-enclave-key.pem; \
    rm /tmp/test-enclave-key.pem

EXPOSE 8443

ENTRYPOINT ["/bin/sh", "-c"]
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
CMD [ "restart-aesmd >&2; exec gramine-sgx tee-self-attestation-test" ]
