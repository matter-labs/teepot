# Scratch Notes for running the teepot vault setup

## Build and Run on SGX server

```bash
$ docker compose build
$ docker compose up
```

## Build and Run on client machine

```bash
❯ cd teepot
❯ gpg --export username@example.com | base64 > gpgkey.pub
❯ export GPG_TTY="$(tty)"
❯ gpg-connect-agent updatestartuptty /bye

❯ RUST_LOG=info cargo run -p vault-unseal --  --sgx-mrsigner c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d     --sgx-allowed-tcb-levels SwHardeningNeeded      --server https://20.172.154.218:8443    init   --unseal-threshold 1 -u bin/tee-vault-admin/tests/data/gpgkey.pub  --admin-threshold 1 -a  bin/tee-vault-admin/tests/data/gpgkey.pub --admin-tee-mrenclave 21c8c1a4dbcce04798f5119eb47203084bc74e564a3c954d1a21172c656cb801
    Finished dev [unoptimized + debuginfo] target(s) in 0.09s
     Running `target/debug/vault-unseal --sgx-mrsigner c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d --sgx-allowed-tcb-levels SwHardeningNeeded --server 'https://20.172.154.218:8443' init --unseal-threshold 1 -u bin/tee-vault-admin/tests/data/gpgkey.pub --admin-threshold 1 -a bin/tee-vault-admin/tests/data/gpgkey.pub --admin-tee-mrenclave 21c8c1a4dbcce04798f5119eb47203084bc74e564a3c954d1a21172c656cb801`
2023-08-23T14:47:56.902422Z  INFO tee_client: Getting attestation report
2023-08-23T14:47:57.340877Z  INFO tee_client: Checked or set server certificate public key hash `b4bf52fdb37431c8531fb310be389c2d17ad9bd41d662e10308c9147c007d0d0`
2023-08-23T14:47:57.741599Z  INFO tee_client: Verifying attestation report
2023-08-23T14:47:57.763320Z  INFO tee_client: TcbLevel is allowed: SwHardeningNeeded: Software hardening is needed
2023-08-23T14:47:57.763356Z  WARN tee_client: Info: Advisory ID: INTEL-SA-00615
2023-08-23T14:47:57.763371Z  INFO tee_client: Report data matches `b4bf52fdb37431c8531fb310be389c2d17ad9bd41d662e10308c9147c007d0d0`
2023-08-23T14:47:57.763391Z  INFO tee_client: mrsigner `c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d` matches
2023-08-23T14:47:57.763412Z  INFO vault_unseal: Quote verified! Connection secure!
2023-08-23T14:47:57.763418Z  INFO vault_unseal: Initializing vault
2023-08-23T14:48:07.278090Z  INFO vault_unseal: Got Response: {"unseal_keys":["wcDMA9FaOxXbOhL7AQv7BoGfG5K+78RHV6LGqT5k/M1e8GP3pvBHTeY1lReCo2bkLmm4k4KBxdqNLSE8lV4urN5iWTAt74jCoC+uuAeA2OSL7AidX+HcftzcAXhJp2INtkyqsL8xGaPgpZxXj77fJ/Z7HW1mUlAxJowdZudvA5DmJls6u8VK6YtY3deLGbMRVygXFG+NGabNrRQ0nnFMMMCPXZ39ETitJyfFX6x4BizVQixagN9IqkozXLiupoHD4N0LOESDIm2MuqPnGAk0X6YgyZhFZc8uCrN9W/zNkXQ7eJxIamsLysVnPGaNQ92VQlz4aFAJLKrMCvGrtrxQJk9N+P47EArGCl9bP2hXfg783arXF6Bp/YgGgpvJRFZ04nMNDlIcIFuV5QBfiJX1hNIXg0MVlqmzVeGDVHlys+2mOvOO8seIBG1p4FGRQr6YWI4KxaN6sVA5DNclvITWiH/6H50SUJqXQ5M6rfEoBajYenpzZwYXb0oGzVHrUg5AnfPSuYRT0p8dAPz3/9vE0nEBzNeNVedEwwbgHP1aSPK8J3pPgoRVMyiq7gXzJEXoG5PLJEq4poQ1QwevAVTNv5Pu/TvTacDkJfVcBL5fukB9fj/WJktxEXmznEK3GMBBmvIAVLkgCEl+dH17CxvKq2ik6AfAHVdmEPcNw0ViNCZj1Q=="]}
{"unseal_keys":["wcDMA9FaOxXbOhL7AQv7BoGfG5K+78RHV6LGqT5k/M1e8GP3pvBHTeY1lReCo2bkLmm4k4KBxdqNLSE8lV4urN5iWTAt74jCoC+uuAeA2OSL7AidX+HcftzcAXhJp2INtkyqsL8xGaPgpZxXj77fJ/Z7HW1mUlAxJowdZudvA5DmJls6u8VK6YtY3deLGbMRVygXFG+NGabNrRQ0nnFMMMCPXZ39ETitJyfFX6x4BizVQixagN9IqkozXLiupoHD4N0LOESDIm2MuqPnGAk0X6YgyZhFZc8uCrN9W/zNkXQ7eJxIamsLysVnPGaNQ92VQlz4aFAJLKrMCvGrtrxQJk9N+P47EArGCl9bP2hXfg783arXF6Bp/YgGgpvJRFZ04nMNDlIcIFuV5QBfiJX1hNIXg0MVlqmzVeGDVHlys+2mOvOO8seIBG1p4FGRQr6YWI4KxaN6sVA5DNclvITWiH/6H50SUJqXQ5M6rfEoBajYenpzZwYXb0oGzVHrUg5AnfPSuYRT0p8dAPz3/9vE0nEBzNeNVedEwwbgHP1aSPK8J3pPgoRVMyiq7gXzJEXoG5PLJEq4poQ1QwevAVTNv5Pu/TvTacDkJfVcBL5fukB9fj/WJktxEXmznEK3GMBBmvIAVLkgCEl+dH17CxvKq2ik6AfAHVdmEPcNw0ViNCZj1Q=="]}

❯ echo wcDMA9FaOxXbOhL7AQv7BoGfG5K+78RHV6LGqT5k/M1e8GP3pvBHTeY1lReCo2bkLmm4k4KBxdqNLSE8lV4urN5iWTAt74jCoC+uuAeA2OSL7AidX+HcftzcAXhJp2INtkyqsL8xGaPgpZxXj77fJ/Z7HW1mUlAxJowdZudvA5DmJls6u8VK6YtY3deLGbMRVygXFG+NGabNrRQ0nnFMMMCPXZ39ETitJyfFX6x4BizVQixagN9IqkozXLiupoHD4N0LOESDIm2MuqPnGAk0X6YgyZhFZc8uCrN9W/zNkXQ7eJxIamsLysVnPGaNQ92VQlz4aFAJLKrMCvGrtrxQJk9N+P47EArGCl9bP2hXfg783arXF6Bp/YgGgpvJRFZ04nMNDlIcIFuV5QBfiJX1hNIXg0MVlqmzVeGDVHlys+2mOvOO8seIBG1p4FGRQr6YWI4KxaN6sVA5DNclvITWiH/6H50SUJqXQ5M6rfEoBajYenpzZwYXb0oGzVHrUg5AnfPSuYRT0p8dAPz3/9vE0nEBzNeNVedEwwbgHP1aSPK8J3pPgoRVMyiq7gXzJEXoG5PLJEq4poQ1QwevAVTNv5Pu/TvTacDkJfVcBL5fukB9fj/WJktxEXmznEK3GMBBmvIAVLkgCEl+dH17CxvKq2ik6AfAHVdmEPcNw0ViNCZj1Q== | base64 --decode | gpg -dq | RUST_LOG=info cargo run -p vault-unseal --  --sgx-mrsigner c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d     --sgx-allowed-tcb-levels SwHardeningNeeded      --server https://20.172.154.218:8443    unseal
    Finished dev [unoptimized + debuginfo] target(s) in 0.09s
     Running `target/debug/vault-unseal --sgx-mrsigner c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d --sgx-allowed-tcb-levels SwHardeningNeeded --server 'https://20.172.154.218:8443' unseal`
2023-08-23T14:48:20.735605Z  INFO tee_client: Getting attestation report
2023-08-23T14:48:21.349424Z  INFO tee_client: Checked or set server certificate public key hash `b4bf52fdb37431c8531fb310be389c2d17ad9bd41d662e10308c9147c007d0d0`
2023-08-23T14:48:21.742086Z  INFO tee_client: Verifying attestation report
2023-08-23T14:48:21.757960Z  INFO tee_client: TcbLevel is allowed: SwHardeningNeeded: Software hardening is needed
2023-08-23T14:48:21.757996Z  WARN tee_client: Info: Advisory ID: INTEL-SA-00615
2023-08-23T14:48:21.758014Z  INFO tee_client: Report data matches `b4bf52fdb37431c8531fb310be389c2d17ad9bd41d662e10308c9147c007d0d0`
2023-08-23T14:48:21.758039Z  INFO tee_client: mrsigner `c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d` matches
2023-08-23T14:48:21.758060Z  INFO vault_unseal: Quote verified! Connection secure!
2023-08-23T14:48:21.758065Z  INFO vault_unseal: Unsealing vault
2023-08-23T14:49:28.144877Z  INFO vault_unseal: Vault is unsealed!
Vault is unsealed!

```

With `teepot-vault-admin-sgx-azure` being the name of the image running the teepot-vault-admin-sgx-azure service, the
following commands can be used
to sign the admin tee:

```bash
❯ (id=$(docker create teepot-vault-admin-sgx-azure); docker cp $id:/app/teepot-vault-admin-sgx-azure.sig ~/teepot-vault-admin-sgx-azure.sig; docker rm -v $id)
❯ cargo run -p vault-admin -- create-sign-request --tee-name admin ~/teepot-vault-admin-sgx-azure.sig > ~/sign_admin_tee.json
❯ vim sign_admin_tee.json
❯ gpg --local-user test@example.com --detach-sign --armor ~/sign_admin_tee.json
❯ RUST_LOG=info cargo run -p vault-admin -- \
  sign-tee \
  --sgx-mrenclave c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d \
  --sgx-allowed-tcb-levels SwHardeningNeeded \
  --server https://127.0.0.1:8444 \
  --out new_admin.sig \
  ~/sign_admin_tee.json ~/sign_admin_tee.json.asc

❯ gramine-sgx-sigstruct-view new_admin.sig
Attributes:
    mr_signer: 8392a970ea57f1f37fb8985d9394b26611b18a5d5591b7d9d58d23998a116298
    mr_enclave: 080c3210d5b6bcf47887101a554c117c21d80e75240bb70846c3e158a713ec65
    isv_prod_id: 0
    isv_svn: 0
    debug_enclave: False

❯ RUST_LOG=info cargo run -p vault-admin -- digest  --sgx-mrsigner 8392a970ea57f1f37fb8985d9394b26611b18a5d5591b7d9d58d23998a116298   --sgx-allowed-tcb-levels SwHardeningNeeded   --server https://127.0.0.1:8444
    Finished dev [unoptimized + debuginfo] target(s) in 0.12s
     Running `target/debug/vault-admin digest --sgx-mrsigner 8392a970ea57f1f37fb8985d9394b26611b18a5d5591b7d9d58d23998a116298 --sgx-allowed-tcb-levels SwHardeningNeeded --server 'https://127.0.0.1:8444'`
2023-09-01T09:13:40.502841Z  INFO vault_admin: Quote verified! Connection secure!
2023-09-01T09:13:40.503374Z  INFO tee_client: Getting attestation report
2023-09-01T09:13:40.810238Z  INFO tee_client: Checked or set server certificate public key hash `6296a59283e8b70b5501cf391457bd618159df4c206a4c5b206afc5b324cdd91`
2023-09-01T09:13:41.110855Z  INFO tee_client: Verifying attestation report
2023-09-01T09:13:41.131057Z  INFO tee_client: TcbLevel is allowed: SwHardeningNeeded: Software hardening is needed
2023-09-01T09:13:41.131099Z  WARN tee_client: Info: Advisory ID: INTEL-SA-00615
2023-09-01T09:13:41.131121Z  INFO tee_client: Report data matches `6296a59283e8b70b5501cf391457bd618159df4c206a4c5b206afc5b324cdd91`
2023-09-01T09:13:41.131143Z  INFO tee_client: mrsigner `8392a970ea57f1f37fb8985d9394b26611b18a5d5591b7d9d58d23998a116298` matches
{
  "last_digest": "c9929fef9c87b5c7bb7c47b563c83c4609741245847f173de0bedb2b3a00daa8"
}

```

```bash
❯ docker compose build && (docker compose rm; docker volume rm teepot_vault-storage teepot_ha-raft-1 teepot_ha-raft-2 teepot_ha-raft-3; docker compose up --remove-orphans vault-1 tvu-1)
❯ (id=$(docker create teepot-vault-admin-sgx-azure); docker cp $id:/app/teepot-vault-admin-sgx-azure.sig ~/teepot-vault-admin-sgx-azure.sig; docker rm -v $id)
❯ gramine-sgx-sigstruct-view ~/teepot-vault-admin-sgx-azure.sig
Attributes:
    mr_signer: c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d
    mr_enclave: 265ca491bf13e2486fd67d12038fcce02f133c5d91277e42f58c0ab464d5b46b
    isv_prod_id: 0
    isv_svn: 0
    debug_enclave: False
❯ RUST_LOG=info cargo run -p vault-unseal --  --sgx-mrsigner c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d     --sgx-allowed-tcb-levels SwHardeningNeeded      --server https://127.0.0.1:8413    init   --unseal-threshold 1 -u tests/data/gpgkey.pub  --admin-threshold 1 -a  tests/data/gpgkey.pub --admin-tee-mrenclave 265ca491bf13e2486fd67d12038fcce02f133c5d91277e42f58c0ab464d5b46b
❯ export GPG_TTY=$(tty)
❯ gpg-connect-agent updatestartuptty /bye >/dev/null
❯ gpg-connect-agent reloadagent /bye
OK
❯ echo wcDMA9FaOxXbOhL7AQwAgMxP/gTv/3RY/lMGPyEAfmIgIRdvfkWf8Sl07blUXmMKfIYyTkksMZLNc0Kiqx1oUR1qbT85WjWDhwhWADEbIhNFnTGdZ/CI24Bl4Nc8Dv7EnvJ0hmJw5AydE5YHACktSYTVgqXR9W8j5BO5K/+LyudJaMvcZFJH44MwYL8hMDKZbIdvIVFFEg2O/cBQgZc+UHljZEX+ptmR1q4BJM0dK6Ol5+v+zQ8FiByf6wgXJ2SQCERkhkiAaKkcIpyW1q8zgqVy29e46B6hfalYe0wD7U9L4QPiAr7Ik8rHEXB5iQucyDuWj65CVJXPVZ2Y+Q1Fk+OPrtYe7yDqZwJs3SlgzI7GNL4x7UqWALhroYzbiWETNwlhF4UZLOQRP5gkCQlAP3LkJJAFtUAbeJy8IgMRCz4F4f8nUCVLf6MDelr9ZXukmuc9U0tkmidNO8R2QAQUMLCCLUCkNnNa/hZz+81EUcNrI24kGqTlZfJxBpc+nr3MJxqSQ+btvqt8eJWlP9UJ0nEBdm74wj7nsekgwwttyq77Z8lciHgTLsjtSwk4tMse6uedWcPEGXxDKGzLd3dyaQD96NCUYt/GbGXVYTkH5mZci59+fkbGFEsJZYGffFmt7pcL69aoctgEKwBUxVR+BESo+UV1qUKAfO92QTYeXCA4/A==  | base64 --decode | gpg -dq | RUST_LOG=info cargo run -p vault-unseal --  --sgx-mrsigner c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d     --sgx-allowed-tcb-levels SwHardeningNeeded      --server https://127.0.0.1:8413    unseal Please enter the passphrase to unlock the OpenPGP secret key:
"test <test@example.com>"
3072-bit RSA key, ID D15A3B15DB3A12FB,
created 2023-08-08 (main key ID 6D728F29A2DBABF8).

Passphrase:
❯ (id=$(docker create teepot-stress); docker cp $id:/app/tee-stress-client.sig ~/tee-stress-client.sig; docker rm -v $id)


```

## Kubernetes

Find out the `mr_enclave` value of the teepot-vault-admin-sgx-azure enclave and extract the sigstruct file:

```bash
❯ docker run -v .:/mnt --pull always -it matterlabsrobot/teepot-vault-admin-sgx-azure:latest 'gramine-sgx-sigstruct-view teepot-vault-admin-sgx-azure.sig; cp teepot-vault-admin-sgx-azure.sig /mnt'
[...]
Attributes:
    mr_signer: c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d
    mr_enclave: 98a540dd7056584e2009c7cf7374f932fbb8e30a4c66cc815c9809620653f751
    isv_prod_id: 0
    isv_svn: 0
    debug_enclave: False
❯ ls -l ~/teepot-vault-admin-sgx-azure.sig
-rw-r--r--. 1 harald harald 1808  2. Nov 10:46 teepot-vault-admin-sgx-azure.sig
```

Start the vault service and pod and forward the port

```bash
❯ kubectl apply \
  -f examples/k8s/data-1-persistentvolumeclaim.yaml \
  -f examples/k8s/vault-1-pod.yaml \
  -f examples/k8s/vault-1-service.yaml
❯ kubectl port-forward pods/vault-1 8443
```

Initialize the instance.
This can take up to 6 minutes, depending on the `performance_multiplier` setting in vault.
Adjust the `--admin-tee-mrenclave` parameter to match the `mr_enclave` value of the teepot-vault-admin-sgx-azure
container.

```bash
❯ RUST_LOG=info cargo run -p vault-unseal --  \
  --sgx-mrsigner c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d \
  --sgx-allowed-tcb-levels SwHardeningNeeded \
  --server https://127.0.0.1:8443 \
  init \
  --unseal-threshold 1 \
  --unseal-pgp-key-file ./tests/data/gpgkey.pub \
  --admin-threshold 1 \
  --admin-pgp-key-file  ./tests/data/gpgkey.pub \
  --admin-tee-mrenclave 98a540dd7056584e2009c7cf7374f932fbb8e30a4c66cc815c9809620653f751
```

Unseal the instance

```bash
❯ echo <one of the unseal secrets from the init output> \
    | base64 --decode \
    | gpg -dq \
    | RUST_LOG=info cargo run -p vault-unseal -- \
    --sgx-mrsigner c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d \
    --sgx-allowed-tcb-levels SwHardeningNeeded \
    --server https://127.0.0.1:8443 \
    unseal
```

End the port forwarding of vault-1 and start the rest of the nodes:

```bash
❯ kubectl apply -f examples/k8s
```

Unseal the other vault instances:

Every unseal secret holder has to do it, until the threshold is reached.

```bash
❯ kubectl port-forward pods/vault-$NUM 8443
❯ echo <one of the unseal secrets from the init output> \
    | base64 --decode \
    | gpg -dq \
    | RUST_LOG=info cargo run -p vault-unseal -- \
    --sgx-mrsigner c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d \
    --sgx-allowed-tcb-levels SwHardeningNeeded \
    --server https://127.0.0.1:8443 \
    unseal
❯ kubectl port-forward pods/vault-3 8443
❯ echo <one of the unseal secrets from the init output> \
    | base64 --decode \
    | gpg -dq \
    | RUST_LOG=info cargo run -p vault-unseal -- \
    --sgx-mrsigner c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d \
    --sgx-allowed-tcb-levels SwHardeningNeeded \
    --server https://127.0.0.1:8443 \
    unseal
```

The vault cluster should now settle to be completely unsealed and synced.

Start the vault-admin pod and forward the port:

```bash
❯ kubectl port-forward pods/teepot-vault-admin-sgx-azure 8444
```

Next is to sign the admin tee with the vault-admin tool:

```bash
❯ cargo run -p vault-admin -- create-sign-request --tee-name admin ~/teepot-vault-admin-sgx-azure.sig > ~/teepot-vault-admin-sgx-azure.json
❯ gpg --local-user test@example.com --detach-sign --armor ~/teepot-vault-admin-sgx-azure.json
❯ cargo run -p vault-admin -- command \
  --server https://127.0.0.1:8444 \
  --sgx-allowed-tcb-levels SwHardeningNeeded \
  --out ~/teepot-vault-admin-sgx-azure-new.sig \
  ~/teepot-vault-admin-sgx-azure.json ~/teepot-vault-admin-sgx-azure.json.asc
```

Then replace `teepot-vault-admin-sgx-azure.sig` with `teepot-vault-admin-sgx-azure-new.sig` in the container
image `matterlabsrobot/teepot-vault-admin-sgx-azure:latest` with this Dockerfile:

```Dockerfile
FROM matterlabsrobot/teepot-vault-admin-sgx-azure:latest
COPY teepot-vault-admin-sgx-azure-new.sig /app/teepot-vault-admin-sgx-azure.sig
```

Build and push the new image:

```bash
❯ docker build -t matterlabsrobot/teepot-vault-admin-sgx-azure-signed:latest .
❯ docker push matterlabsrobot/teepot-vault-admin-sgx-azure-signed:latest
```

Delete the old vault-admin pod and start the new one:

```bash
❯ kubectl delete pod/teepot-vault-admin-sgx-azure
❯ kubectl apply -f examples/k8s/vault-admin-signed-pod.yaml
```

The new signed admin tee can now be used.
