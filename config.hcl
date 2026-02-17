ui            = true
cluster_name  = "tokenizationservice-vault"
disable_mlock = true

storage "raft" {
  path    = "/vault/data"
  node_id = "vault-1"
}

listener "tcp" {
  address = "0.0.0.0:8200"

  # Turn ON TLS
  tls_cert_file = "/certs/server.pem"   # chain (leaf + intermediates)
  tls_key_file  = "/certs/server.key"
  tls_min_version = "tls12"

  # Require client certs (mTLS)
  tls_require_and_verify_client_cert = true
  tls_client_ca_file = "/certs/client_ca.pem"
}

# Use HTTPS addrs once TLS is enabled (match SANs in server.pem)
api_addr     = "https://vault1.poc.tokenizationservice.com:8200"
cluster_addr = "https://vault1.poc.tokenizationservice.com:8201"

