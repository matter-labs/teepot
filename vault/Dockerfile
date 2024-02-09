FROM docker.io/ubuntu:focal

RUN set -eux; \
    apt-get update; \
    apt-get install -y curl gpg;

RUN set -eux; \
    curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg; \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg]  https://packages.gramineproject.io/ focal main" > /etc/apt/sources.list.d/gramine.list

RUN set -eux; \
    curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key; \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" > /etc/apt/sources.list.d/intel-sgx.list

RUN set -eux; \
    curl -fsSLo /usr/share/keyrings/microsoft.asc https://packages.microsoft.com/keys/microsoft.asc; \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.asc] https://packages.microsoft.com/ubuntu/20.04/prod focal main" > /etc/apt/sources.list.d/msprod.list

# Install gramine
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y gramine \
    libsgx-urts \
    libsgx-enclave-common \
    libsgx-dcap-quote-verify \
    az-dcap-client \
    psmisc \
    ;

RUN set -eux; \
    curl -s -o - https://apt.releases.hashicorp.com/gpg | gpg --dearmor > /usr/share/keyrings/hashicorp-archive-keyring.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com focal main" > /etc/apt/sources.list.d/hashicorp.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends vault libcap2-bin;

RUN rm -rf /var/lib/apt/lists/*

WORKDIR /opt/vault
COPY vault/vault.manifest.toml vault/config.hcl vault/vault-csr.conf vault/cakey.pem vault/cacert.pem vault/start.sh ./
RUN mkdir -p /opt/vault/data /opt/vault/.cache /opt/vault/tls && rm -rf /opt/vault/tls/*

COPY vault/enclave-key.pem /tmp/
RUN set -eux; \
    find / -xdev -print0 | xargs -0 touch -r /usr/bin/vault || : ; \
    gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu -Dexecdir=/usr/bin -Dlog_level=warning vault.manifest.toml vault.manifest; \
    gramine-sgx-sign --manifest vault.manifest --output vault.manifest.sgx --key /tmp/enclave-key.pem; \
    rm /tmp/enclave-key.pem

VOLUME /opt/vault/tls
VOLUME /opt/vault/data

ENTRYPOINT ["/bin/sh", "-c"]
CMD [ "/restart_aesm.sh ; exec gramine-sgx vault" ]
