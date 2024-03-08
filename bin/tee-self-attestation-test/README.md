# self-attestation-test

## Azure DCAP

```bash
❯ docker run -i --init --rm --privileged  --device /dev/sgx_enclave --net host \
    matterlabsrobot/teepot-self-attestation-test-sgx-azure:latest \
    | base64 -d --ignore-garbage \
    | docker run -i --init --rm --net host matterlabsrobot/verify-attestation-sgx-azure:latest

aesm_service: warning: Turn to daemon. Use "--no-daemon" option to execute in foreground.
Gramine is starting. Parsing TOML manifest file, this may take some time...
Verifying quote (4734 bytes)...
Quote verification result: SwHardeningNeeded: Software hardening is needed
	Info: Advisory ID: INTEL-SA-00615
Quote verified successfully: SwHardeningNeeded: Software hardening is needed
mrsigner: c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d
mrenclave: 23267adf8144a195ede71425c50529ac8fd1aa896fe91786c28406854f246ab9
reportdata: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

## PCCS DCAP

Install iptables rules to forward traffic to 127.0.0.1:8081 to the PCCS server.

```bash
❯ sudo sysctl -w net.ipv4.conf.all.route_localnet=1
❯ sudo iptables -t nat -A OUTPUT -p tcp --dport 8081 -j DNAT --to-destination 192.168.122.1:8081
❯ sudo iptables -t nat -A POSTROUTING -j MASQUERADE
```

```bash
❯ docker run -i --init --rm --privileged --device /dev/sgx_enclave --net host \
    matterlabsrobot/teepot-self-attestation-test-sgx-dcap:latest \
    | base64 -d --ignore-garbage \
    | docker run -i --init --rm --net host \
    -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf \
    matterlabsrobot/verify-attestation-sgx-dcap:latest

aesm_service: warning: Turn to daemon. Use "--no-daemon" option to execute in foreground.
Gramine is starting. Parsing TOML manifest file, this may take some time...
Verifying quote (4730 bytes)...
Quote verified successfully: Ok
mrsigner: c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d
mrenclave: 10cfeee8e2a65c31795104d041647415c01dc3ae4b004e05e26107f6ede82677
reportdata: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

On an outdated machine, this might look like this:

```bash
❯ docker run -i --init --rm --privileged --device /dev/sgx_enclave --net host \
                matterlabsrobot/teepot-self-attestation-test-sgx-dcap:latest \
                | base64 -d --ignore-garbage \
                | docker run -i --init --rm --net host \
                -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf \
                matterlabsrobot/verify-attestation-sgx-dcap:latest

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
mrenclave: 10cfeee8e2a65c31795104d041647415c01dc3ae4b004e05e26107f6ede82677
reportdata: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```
