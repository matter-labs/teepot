```bash
❯ idents=( tests/data/pub*.asc )
❯ cargo run --bin vault-admin -p vault-admin -- \
  verify \
    ${idents[@]/#/-i } \
    tests/data/test.json \
    tests/data/test.json.asc

Verified signature for `81A312C59D679D930FA9E8B06D728F29A2DBABF8`

❯ RUST_LOG=info cargo run -p vault-admin -- \
  send \
   --sgx-mrsigner c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d \
   --sgx-allowed-tcb-levels SwHardeningNeeded \
   --server https://127.0.0.1:8444 \
  bin/tee-vault-admin/tests/data/test.json \
  bin/tee-vault-admin/tests/data/test.json.asc

2023-08-04T10:51:14.919941Z  INFO vault_admin: Quote verified! Connection secure!
2023-08-04T10:51:14.920430Z  INFO tee_client: Getting attestation report
2023-08-04T10:51:15.020459Z  INFO tee_client: Checked or set server certificate public key hash `f6dc06b9f2a14fa16a94c076a85eab8513f99ec0091801cc62c8761e42908fc1`
2023-08-04T10:51:15.024310Z  INFO tee_client: Verifying attestation report
2023-08-04T10:51:15.052712Z  INFO tee_client: TcbLevel is allowed: SwHardeningNeeded: Software hardening is needed
2023-08-04T10:51:15.054508Z  WARN tee_client: Info: Advisory ID: INTEL-SA-00615
2023-08-04T10:51:15.054572Z  INFO tee_client: Report data matches `f6dc06b9f2a14fa16a94c076a85eab8513f99ec0091801cc62c8761e42908fc1`
2023-08-04T10:51:15.054602Z  INFO tee_client: mrsigner `c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d` matches
[
  {
    "request": {
      "data": {
        "lease": "1000",
        "name": "test",
        "sgx_allowed_tcb_levels": "Ok,SwHardeningNeeded",
        "sgx_mrsigner": "c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d",
        "token_policies": "test",
        "types": "sgx"
      },
      "url": "/v1/auth/tee/tees/test"
    },
    "response": {
      "status_code": 204,
      "value": null
    }
  }
]
```
