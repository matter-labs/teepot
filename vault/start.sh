#!/bin/bash
set -e
if [ ! -f /opt/vault/tls/tls.ok ]; then
  # Generate the TLS certificates
  cd /opt/vault/tls
  cp ../cacert.pem ../cakey.pem ../vault-csr.conf .
  openssl req -new -newkey rsa:4096 -keyout tls.key -out vault.csr \
                   -config vault-csr.conf -extensions v3_req
  openssl x509 -req -in vault.csr -days 365 -CA cacert.pem -CAkey cakey.pem -CAcreateserial \
                   -out tls_single.crt -extensions v3_req -extfile vault-csr.conf
  cat tls_single.crt cacert.pem >> tls.crt
  echo ok > tls.ok
fi
cd /opt/vault

# Start the vault server
exec vault server -config=/opt/vault/config.hcl -log-level=trace
