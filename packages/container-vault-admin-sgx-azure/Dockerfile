# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs

FROM teepot-vault-admin-sgx-azure:base

WORKDIR /app

COPY packages/container-vault-sgx-azure/test-enclave-key.pem /tmp/

RUN set -eux; \
    gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu \
      -Dentrypoint=$(readlink /bin/tee-vault-admin) \
      -Dexecdir=/bin \
      -Dlog_level=warning \
      tee-vault-admin.manifest.toml tee-vault-admin.manifest; \
    gramine-sgx-sign --manifest tee-vault-admin.manifest --output tee-vault-admin.manifest.sgx --key /tmp/test-enclave-key.pem; \
    rm /tmp/test-enclave-key.pem

VOLUME /opt/vault/tls

EXPOSE 8443

ENTRYPOINT ["/bin/sh", "-c"]
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
CMD [ "echo tee-vault-admin in SGX mode starting; [[ -r /var/run/aesmd/aesm.socket ]] || restart-aesmd ; exec gramine-sgx tee-vault-admin" ]
