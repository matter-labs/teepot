# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ teepot }:
teepot.container-self-attestation-test-sgx-azure.override {
  container-name = "teepot-self-attestation-test-sgx-dcap";
  isAzure = false;
}
