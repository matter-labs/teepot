# Era Proof Attestation Verifier

This tool verifies the SGX/TDX attestations and signatures for zkSync Era L1 batches.

## Usage

Basic usage with attestation policy provided from a YAML file:

```bash
verify-era-proof-attestation --rpc https://mainnet.era.zksync.io \
    --continuous 493220 \
    --attestation-policy-file examples/attestation_policy.yaml \
    --log-level info
```

## Attestation Policy Configuration

You can specify the attestation policy either through command-line arguments or by providing a YAML configuration file.

### Command-line Arguments

The following command-line arguments are available:

- `--batch`, `-n <BATCH>`: The batch number or range of batch numbers to verify the attestation and signature (e.g., "
  42" or "42-45"). Mutually exclusive with `--continuous`.
- `--continuous <FIRST_BATCH>`: Continuous mode: keep verifying new batches starting from the specified batch number
  until interrupted. Mutually exclusive with `--batch`.
- `--rpc <URL>`: URL of the RPC server to query for the batch attestation and signature.
- `--chain <CHAIN_ID>`: Chain ID of the network to query (default: L2ChainId::default()).
- `--rate-limit <MILLISECONDS>`: Rate limit between requests in milliseconds (default: 0).
- `--log-level <LEVEL>`: Log level for the log output. Valid values are: `off`, `error`, `warn`, `info`, `debug`,
  `trace` (default: `warn`).
- `--attestation-policy-file <PATH>`: Path to a YAML file containing attestation policy configuration. This overrides
  any attestation policy settings provided via command line options.

Either `--batch` or `--continuous` mode must be specified.

### YAML Configuration File

The attestation policy is loaded from a YAML file using the `--attestation-policy-file` option.

Example YAML configuration file:

```yaml
sgx:
  mrenclaves:
    - a2caa7055e333f69c3e46ca7ba65b135a86c90adfde2afb356e05075b7818b3c
    - 36eeb64cc816f80a1cf5818b26710f360714b987d3799e757cbefba7697b9589
    - 4a8b79e5123f4dbf23453d583cb8e5dcf4d19a6191a0be6dd85b7b3052c32faf
    - 1498845b3f23667356cc49c38cae7b4ac234621a5b85fdd5c52b5f5d12703ec9
    - 1b2374631bb2572a0e05b3be8b5cdd23c42e9d7551e1ef200351cae67c515a65
    - 6fb19e47d72a381a9f3235c450f8c40f01428ce19a941f689389be3eac24f42a
    - b610fd1d749775cc3de88beb84afe8bb79f55a19100db12d76f6a62ac576e35d
    - a0b1b069b01bdcf3c1517ef8d4543794a27ed4103e464be7c4afdc6136b42d66
    - 71e2a11a74b705082a7286b2008f812f340c0e4de19f8b151baa347eda32d057
    - d5a0bf8932d9a3d7af6d9405d4c6de7dcb7b720bb5510666b4396fc58ee58bb2
  allowed_tcb_levels:
    - Ok
    - SwHardeningNeeded
  allowed_advisory_ids:
    - INTEL-SA-00615
tdx:
  mrs:
    - - 2a90c8fa38672cafd791d994beb6836b99383b2563736858632284f0f760a6446efd1e7ec457cf08b629ea630f7b4525
      - 3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304f
      - c08ab64725566bcc8a6fb1c79e2e64744fcff1594b8f1f02d716fb66592ecd5de94933b2bc54ffbbc43a52aab7eb1146
      - 092a4866a9e6a1672d7439a5d106fbc6eb57b738d5bfea5276d41afa2551824365fdd66700c1ce9c0b20542b9f9d5945
      - 971fb52f90ec98a234301ca9b8fc30b613c33e3dd9c0cc42dcb8003d4a95d8fb218b75baf028b70a3cabcb947e1ca453
    - - 2a90c8fa38672cafd791d994beb6836b99383b2563736858632284f0f760a6446efd1e7ec457cf08b629ea630f7b4525
      - 3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304f
      - c08ab64725566bcc8a6fb1c79e2e64744fcff1594b8f1f02d716fb66592ecd5de94933b2bc54ffbbc43a52aab7eb1146
      - 092a4866a9e6a1672d7439a5d106fbc6eb57b738d5bfea5276d41afa2551824365fdd66700c1ce9c0b20542b9f9d5945
      - f57bb7ed82c6ae4a29e6c9879338c592c7d42a39135583e8ccbe3940f2344b0eb6eb8503db0ffd6a39ddd00cd07d8317
  allowed_tcb_levels:
    - Ok
```
