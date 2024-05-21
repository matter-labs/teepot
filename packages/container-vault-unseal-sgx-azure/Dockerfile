# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs

FROM teepot-vault-unseal-sgx-azure:base

WORKDIR /app

COPY packages/container-vault-sgx-azure/test-enclave-key.pem /tmp/

RUN set -eux; \
    gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu \
      -Dentrypoint=$(readlink /bin/tee-vault-unseal) \
      -Dvault_auth_tee_sha=1505ffe3ef0994de63206ccce1dec6715d55e72955960cb7314e4571811c4422 \
      -Dvault_auth_tee_version=0.1.0+dev \
      -Dexecdir=/bin \
      -Dlog_level=warning \
      tee-vault-unseal.manifest.toml tee-vault-unseal.manifest; \
    gramine-sgx-sign --manifest tee-vault-unseal.manifest --output tee-vault-unseal.manifest.sgx --key /tmp/test-enclave-key.pem; \
    rm /tmp/test-enclave-key.pem

EXPOSE 8443

ENTRYPOINT ["/bin/sh", "-c"]
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
CMD [ "echo tee-vault-unseal in SGX mode starting; [[ -r /var/run/aesmd/aesm.socket ]] || restart-aesmd ; exec gramine-sgx tee-vault-unseal" ]
