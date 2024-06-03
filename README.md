# teepot

Key Value store in a TEE with Remote Attestation for Authentication

## Introduction

This project is a key-value store that runs in a Trusted Execution Environment (TEE) and uses Remote Attestation for
Authentication.
The key-value store is implemented using Hashicorp Vault running in an Intel SGX enclave via the Gramine runtime.

## Parts of this project

- `teepot`: The main rust crate that abstracts TEEs and key-value stores.
- `tee-vault-unseal`: An enclave that uses the Vault API to unseal a vault as a proxy.
- `vault-unseal`: A client utility, that talks to `tee-vault-unseal` to unseal a vault.
- `tee-vault-admin`: An enclave that uses the Vault API to administer a vault as a proxy.
- `vault-admin`: A client utility, that talks to `tee-vault-admin` to administer a vault.
- `teepot-read` : A pre-exec utility that reads from the key-value store and passes the key-value pairs as environment
  variables to the enclave.
- `teepot-write` : A pre-exec utility that reads key-values from the environment variables and writes them to the
  key-value store.
- `verify-attestation`: A client utility that verifies the attestation of an enclave.
- `tee-key-preexec`: A pre-exec utility that generates a p256 secret key and passes it as an environment variable to the
  enclave along with the attestation quote containing the hash of the public key.

## Development

### Prerequisites

Install [nix](https://zero-to-nix.com/start/install).

In `~/.config/nix/nix.conf`

```ini
experimental-features = nix-command flakes
```

or on nixos in `/etc/nixos/configuration.nix` add the following lines:

```nix
{
  nix = {
    extraOptions = ''
      experimental-features = nix-command flakes
    '';
  };
}
```

Optionally install cachix (to save build time) and use the nixsgx cache:

```shell
$ nix-env -iA cachix -f https://cachix.org/api/v1/install
$ cachix use nixsgx
```

### Develop

```shell
$ nix develop --impure
```

optionally create `.envrc` for `direnv` to automatically load the environment when entering the directory:

```shell
$ cat <<EOF > .envrc
use flake .#teepot
EOF
$ direnv allow
```

### Format for commit

```shell
$ nix run .#fmt
```

### Build as the CI would

```shell
$ nix run github:nixos/nixpkgs/nixos-23.11#nixci
```

### Build and test individual container

See the `packages` directory for the available packages and containers.

```shell
$ nix build -L .#container-vault-sgx-azure
[...]
#8 5.966 Measurement:
#8 5.966     45b9f90fc2562e66516f40c83adc30007c88427d8d9fa7a35718f4cbdeac3efd
[...]
$ docker load -i result
$ docker run -v $(pwd):/mnt -i --init --rm teepot-vault-sgx-azure:latest "cp teepot-vault-sgx-azure.sig /mnt"
$ nix shell github:matter-labs/nixsgx#gramine -c gramine-sgx-sigstruct-view teepot-vault-sgx-azure.sig
Attributes:
    mr_signer: c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d
    mr_enclave: 45b9f90fc2562e66516f40c83adc30007c88427d8d9fa7a35718f4cbdeac3efd
    isv_prod_id: 0
    isv_svn: 0
    debug_enclave: False
```
