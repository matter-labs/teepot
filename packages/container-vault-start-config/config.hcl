# Parameter needed because of slow plugin loading
# may be relaxed for faster machines
#http_read_header_timeout = 0
#http_read_timeout = 300

disable_mlock = true
ui            = false

listener "tcp" {
  address            = "0.0.0.0:8210"
  cluster_address    = "0.0.0.0:8211"
  tls_disable        = false
  tls_cert_file      = "/opt/vault/tls/tls.crt"
  tls_key_file       = "/opt/vault/tls/tls.key"
  tls_client_ca_file = "/opt/vault/cacert.pem"
}

storage "raft" {
  path    = "/opt/vault/data/"
  # override vial env var VAULT_RAFT_NODE_ID
  node_id = "vault-1"

  # Parameter needed because of slow plugin loading
  # may be relaxed for faster machines
  # performance_multiplier = 200
  #autopilot_reconcile_interval = "120s"
  #autopilot_update_interval = "60s"

  retry_join {
    leader_api_addr         = "https://vault-1:8210"
    leader_ca_cert_file     = "/opt/vault/cacert.pem"
    leader_client_cert_file = "/opt/vault/tls/tls.crt"
    leader_client_key_file  = "/opt/vault/tls/tls.key"
  }
  retry_join {
    leader_api_addr         = "https://vault-2:8210"
    leader_ca_cert_file     = "/opt/vault/cacert.pem"
    leader_client_cert_file = "/opt/vault/tls/tls.crt"
    leader_client_key_file  = "/opt/vault/tls/tls.key"
  }
  retry_join {
    leader_api_addr         = "https://vault-3:8210"
    leader_ca_cert_file     = "/opt/vault/cacert.pem"
    leader_client_cert_file = "/opt/vault/tls/tls.crt"
    leader_client_key_file  = "/opt/vault/tls/tls.key"
  }
}

# path of plugin binaries
plugin_directory = "/opt/vault/plugins"

# override via env var VAULT_API_ADDR
api_addr     = "https://vault:8210"
# override via env var VAULT_CLUSTER_ADDR
cluster_addr = "https://vault:8211"
