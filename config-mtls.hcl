ui            = true
cluster_name  = "tokenizationservice-vault"
disable_mlock = true

# Use your public DNS name here:
api_addr     = "https://vault1.poc.tokenizationservice.com:8200"
# Cluster address can be internal DNS or IP:
cluster_addr = "https://vault1.poc.tokenizationservice.com:8201"

storage "raft" {
  path    = "/vault/data"
  node_id = "vault-1"
}

listener "tcp" {
  address = "0.0.0.0:8200"

  # Server cert & key issued by PKI (we’ll create these next)
  tls_cert_file = "/certs/server.pem"
  tls_key_file  = "/certs/server.key"

  # CA that signs *client* certificates (our PKI root)
  tls_client_ca_file = "/certs/ca.pem"

  # Enforce client certs for every API call
  tls_require_and_verify_client_cert = "true"
}
