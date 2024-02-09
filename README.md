# teepot
Key Value store in a TEE with Remote Attestation for Authentication

## Introduction

This project is a key-value store that runs in a Trusted Execution Environment (TEE) and uses Remote Attestation for Authentication.
The key-value store is implemented using Hashicorp Vault running in an Intel SGX enclave via the Gramine runtime.

## Parts of this project

- `teepot`: The main rust crate that abstracts TEEs and key-value stores.
- `tee-vault-unseal`: An enclave that uses the Vault API to unseal a vault as a proxy.
- `vault-unseal`: A client utility, that talks to `tee-vault-unseal` to unseal a vault.
- `tee-vault-admin`: An enclave that uses the Vault API to administer a vault as a proxy.
- `vault-admin`: A client utility, that talks to `tee-vault-admin` to administer a vault.
- `teepot-read` : A pre-exec utility that reads from the key-value store and passes the key-value pairs as environment variables to the enclave.
- `teepot-write` : A pre-exec utility that reads key-values from the environment variables and writes them to the key-value store.
- `verify-attestation`: A client utility that verifies the attestation of an enclave.
- `tee-key-preexec`: A pre-exec utility that generates a p256 secret key and passes it as an environment variable to the enclave along with the attestation quote containing the hash of the public key.
