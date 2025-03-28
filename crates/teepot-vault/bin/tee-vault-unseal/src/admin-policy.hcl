# Read system health check
path "sys/health"
{
  capabilities = ["read", "sudo"]
}

# Create and manage ACL policies broadly across Vault

# List existing policies
path "sys/policies/acl"
{
  capabilities = ["list"]
}

# Create and manage ACL policies
path "sys/policies/acl/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Enable and manage authentication methods broadly across Vault

# Manage auth methods broadly across Vault
path "auth/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Create, update, and delete auth methods
path "sys/auth/*"
{
  capabilities = ["create", "update", "delete", "sudo"]
}

# List auth methods
path "sys/auth"
{
  capabilities = ["read"]
}

# Enable and manage the key/value secrets engine at `secret/` path

# List, create, update, and delete key/value secrets
path "secret/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Manage secrets engines
path "sys/mounts/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# List existing secrets engines.
path "sys/mounts"
{
  capabilities = ["read"]
}

# Manage plugins
# https://developer.hashicorp.com/vault/api-docs/system/plugins-catalog
path "sys/plugins/catalog/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# List existing plugins
# https://developer.hashicorp.com/vault/api-docs/system/plugins-catalog
path "sys/plugins/catalog"
{
  capabilities = ["list"]
}

# Reload plugins
# https://developer.hashicorp.com/vault/api-docs/system/plugins-reload-backend
path "sys/plugins/reload/backend"
{
  capabilities = ["create", "update", "sudo"]
}
