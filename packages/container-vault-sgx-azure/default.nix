# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ teepot
, nixsgxLib
, vat
, vault
, container-name ? "teepot-vault-sgx-azure"
, tag ? null
, isAzure ? true
}:
let
  entrypoint = "${teepot.teepot.tee_ratls_preexec}/bin/tee-ratls-preexec";
  appDir = "/opt/vault";
in
nixsgxLib.mkSGXContainer {
  name = container-name;
  inherit tag;
  inherit appDir;

  packages = [
    teepot.teepot.tee_ratls_preexec
    vault
    vat.vault-auth-tee
    teepot.container-vault-start-config
  ];
  inherit entrypoint;

  isAzure = true;

  extraPostBuild = ''
    mkdir -p $out/${appDir}/{data,.cache,tls,plugins}
    ln -s ${vat.vault-auth-tee}/bin/vault-auth-tee $out/opt/vault/plugins
  '';

  manifest = {
    loader = {
      argv = [
        entrypoint
        "--"
        "${vault}/bin/vault"
        "server"
        "-config=/opt/vault/config.hcl"
        "-log-level=trace"
      ];
      log_level = "warning";
      env = {
        VAULT_CLUSTER_ADDR.passthrough = true;
        VAULT_API_ADDR.passthrough = true;
        VAULT_RAFT_NODE_ID.passthrough = true;

        DNS_NAMES = "teepot-vault.teepot-vault,teepot-vault-0.teepot-vault,teepot-vault-1.teepot-vault,teepot-vault-2.teepot-vault";

        # otherwise vault will lock a lot of unused EPC memory
        VAULT_RAFT_INITIAL_MMAP_SIZE = "0";

        # possible tweak option, if problems with raft
        # VAULT_RAFT_DISABLE_MAP_POPULATE = "true"
      };
    };

    fs.mounts = [
      { type = "tmpfs"; path = "/opt/vault/tls"; }
      { type = "encrypted"; path = "/opt/vault/.cache"; uri = "file:/opt/vault/.cache"; key_name = "_sgx_mrsigner"; }
      { type = "encrypted"; path = "/opt/vault/data"; uri = "file:/opt/vault/data"; key_name = "_sgx_mrsigner"; }
    ];

    sgx = {
      debug = false;
      edmm_enable = false;
      enclave_size = "16G";
      max_threads = 128;

      trusted_files = [
        "file:/opt/vault/plugins/"
        "file:/opt/vault/config.hcl"
        "file:/opt/vault/cacert.pem"
        "file:/opt/vault/cakey.pem"
      ];

    };

    sys.stack.size = "16M";
    # vault needs flock
    sys.experimental__enable_flock = true;
  };
}


