# self-attestation-test

Optionally build and load the containers (remove the `matterlabsrobot/` repo from the commands below then)

```bash
$ nix build -L .#container-verify-attestation-sgx && docker load -i result
$ nix build -L .#container-self-attestation-test-sgx-dcap && docker load -i result
$ nix build -L .#container-self-attestation-test-sgx-azure && docker load -i result
```

## Azure DCAP

```bash
❯ docker run -i --init --rm --privileged --device /dev/sgx_enclave \
    matterlabsrobot/teepot-self-attestation-test-sgx-azure:latest \
    | base64 -d --ignore-garbage \
    | docker run -i --rm matterlabsrobot/verify-attestation-sgx:latest -

aesm_service: warning: Turn to daemon. Use "--no-daemon" option to execute in foreground.
Gramine is starting. Parsing TOML manifest file, this may take some time...
Verifying quote (4734 bytes)...
Quote verification result: SwHardeningNeeded: Software hardening is needed
	Info: Advisory ID: INTEL-SA-00615
Quote verified successfully: SwHardeningNeeded: Software hardening is needed
mrsigner: c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d
mrenclave: 31a0d51ee410ed6db18ebfb181ba0b2fa0d2062a38d6b955b73b3e9cfb8336bd
reportdata: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

## Normal DCAP

```bash
❯ docker run -i --init --rm --privileged --device /dev/sgx_enclave \
    matterlabsrobot/teepot-self-attestation-test-sgx-dcap:latest \
    | base64 -d --ignore-garbage \
    | docker run -i --rm matterlabsrobot/verify-attestation-sgx:latest -

aesm_service: warning: Turn to daemon. Use "--no-daemon" option to execute in foreground.
Gramine is starting. Parsing TOML manifest file, this may take some time...
Verifying quote (4730 bytes)...
Quote verified successfully: Ok
mrsigner: c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d
mrenclave: 7ffe70789261a51769f50e129bfafb2aafe91a4e17c3f0d52839006777c652f6
reportdata: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

On an outdated machine, this might look like this:

```bash
❯ docker run -i --init --rm --privileged --device /dev/sgx_enclave \
                matterlabsrobot/teepot-self-attestation-test-sgx-dcap:latest \
                | base64 -d --ignore-garbage \
                | docker run -i --rm matterlabsrobot/verify-attestation-sgx:latest -

aesm_service: warning: Turn to daemon. Use "--no-daemon" option to execute in foreground.
Gramine is starting. Parsing TOML manifest file, this may take some time...
Verifying quote (4600 bytes)...
Quote verification result: OutOfDate: Firmware needs to be updated
	Info: Advisory ID: INTEL-SA-00614
	Info: Advisory ID: INTEL-SA-00617
	Info: Advisory ID: INTEL-SA-00289
	Info: Advisory ID: INTEL-SA-00657
	Info: Advisory ID: INTEL-SA-00767
	Info: Advisory ID: INTEL-SA-00828
	Info: Advisory ID: INTEL-SA-00615
Quote verified successfully: OutOfDate: Firmware needs to be updated
mrsigner: c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d
mrenclave: 7ffe70789261a51769f50e129bfafb2aafe91a4e17c3f0d52839006777c652f6
reportdata: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```
