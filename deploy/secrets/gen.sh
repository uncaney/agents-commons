#!/usr/bin/env bash
# Generate every secret file the stack needs that is missing. Idempotent: never overwrites an
# existing file. Run from deploy/secrets. Real tunnel_token / age_recipient / egress creds must be
# filled by hand (see README); this covers the server-internal ones so the core stack boots.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
rnd(){ openssl rand -hex 32 | tr -d '\n' > "$1"; }
seed(){ head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > "$1"; }  # ed25519 seed, base64url raw
for f in pg_password server_secret admin_token poll_token ops_token check_token courier_token edge_secret; do
  [ -s "$f.txt" ] || { rnd "$f.txt"; echo "generated $f.txt"; }
done
[ -s server_sign_key.txt ] || { seed server_sign_key.txt; echo "generated server_sign_key.txt (ed25519 seed)"; }
[ -e server_online_cert.txt ] || { : > server_online_cert.txt; echo "created empty server_online_cert.txt"; }
# egress-service creds (courier/edge): empty placeholders so compose validates; fill before enabling those services
for f in tunnel_token age_recipient hf_token cf_token cf_kv_token bing_api_key wal_pub edge_secret server_online_cert; do
  [ -e "$f.txt" ] || { : > "$f.txt"; echo "created empty $f.txt (fill before use)"; }
done
chmod 644 ./*.txt  # docker mounts file-secrets with host mode; gateway runs nonroot and must read them
echo "done. REQUIRED by hand: tunnel_token.txt (Cloudflare), age_recipient.txt (age public key)."
