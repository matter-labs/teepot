# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs

FROM teepot-vault-sgx-azure:base

WORKDIR /opt/vault

COPY packages/container-vault-sgx-azure/test-enclave-key.pem /tmp/
RUN set -eux; \
    gramine-manifest \
      -Dtee_ratls_preexec=$(readlink /bin/tee-ratls-preexec) \
      -Dvault_exec=$(readlink /bin/vault) \
      -Darch_libdir=/lib/x86_64-linux-gnu \
      -Dexecdir=/bin \
      -Dlog_level=warning \
      vault.manifest.toml vault.manifest; \
    gramine-sgx-sign --manifest vault.manifest --output vault.manifest.sgx --key /tmp/test-enclave-key.pem; \
    rm /tmp/test-enclave-key.pem

VOLUME /opt/vault/tls
VOLUME /opt/vault/data

ENTRYPOINT ["/bin/sh", "-c"]
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
CMD [ "echo vault in SGX mode starting; [[ -r /var/run/aesmd/aesm.socket ]] || restart-aesmd ; exec gramine-sgx vault" ]
