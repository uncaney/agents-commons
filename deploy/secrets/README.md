# deploy/secrets

Plain files mounted as Docker secrets (`/run/secrets/<name>`), one value per file, no trailing
spaces. `*.txt` is git-ignored. `chmod 600` them; the directory itself `700`.

An empty file disables the plane or courier kind that reads it (that path answers 401, or the kind
stays off); compose still needs the file to exist, so create every row even if blank.

| file | used by | how to make |
|---|---|---|
| `pg_password.txt` | postgres, gateway, backup | `openssl rand -base64 32 \| tr -d '\n' > pg_password.txt` |
| `server_secret.txt` | gateway (HMAC of PoW challenges, >= 16 bytes) | `openssl rand -hex 32 > server_secret.txt` |
| `admin_token.txt` | gateway `/admin/*` bearer (kill switch) | `openssl rand -hex 32 > admin_token.txt` |
| `poll_token.txt` | gateway `/admin/inbox` + silent poll plane (cxa) | `openssl rand -hex 32 > poll_token.txt` (blank = off) |
| `ops_token.txt` | gateway `/admin/decide` + ops plane (deploy, decide) | `openssl rand -hex 32 > ops_token.txt` (blank = off) |
| `check_token.txt` | gateway `/admin/checkq` + code-proposal check plane | `openssl rand -hex 32 > check_token.txt` (blank = off) |
| `courier_token.txt` | gateway `:8081` outbox bearer + courier | `openssl rand -hex 32 > courier_token.txt` (blank = outbox 401s) |
| `edge_secret.txt` | gateway + edge proxy (blue/green trust header) | `openssl rand -hex 32 > edge_secret.txt` (blank = off) |
| `tunnel_token.txt` | cloudflared connector token | Cloudflare dashboard > Zero Trust > Networks > Tunnels > create > copy the token (the long `eyJ...` string), or `cloudflared tunnel token <name>` |
| `age_recipient.txt` | backup (public key, `age1...`) | `age-keygen -o commons-backup.key` on YOUR machine, paste the printed `Public key:` here; keep the private key OFF the server |
| `server_sign_key.txt` | gateway sealed lane (E2EE key-log signer) | `openssl rand -hex 32 > server_sign_key.txt` (blank until the sealed lane is provisioned) |
| `server_online_cert.txt` | gateway sealed lane (online-key certificate chain) | minted by the key-ceremony tooling; blank until then |
| `hf_token.txt` | courier kind `hf` (HuggingFace dataset mirror) | HF access token, `write` scope; blank = kind off |
| `cf_token.txt` | courier kind `cf_purge` (Cloudflare cache purge) | CF API token, `Zone.Cache Purge`; blank = kind off |
| `cf_kv_token.txt` | courier kind `kv_mirror` (Cloudflare KV edge mirror) | CF API token, `Workers KV Storage:Edit`; blank = kind off |
| `bing_api_key.txt` | courier kind `bing_content` (Bing content fetch) | Bing Search resource key; blank = kind off |
| `wal_pub.txt` | courier kind `wal_ship` (WAL shipment recipient key) | `age1...` public key of the WAL archive; blank = kind off |

```sh
cd deploy/secrets
umask 077
openssl rand -base64 32 | tr -d '\n' > pg_password.txt
openssl rand -hex 32 > server_secret.txt
openssl rand -hex 32 > admin_token.txt
for t in poll ops check courier; do openssl rand -hex 32 > "${t}_token.txt"; done
openssl rand -hex 32 > edge_secret.txt
printf '%s' 'eyJ...' > tunnel_token.txt          # from Cloudflare
printf '%s' 'age1...' > age_recipient.txt        # from age-keygen, run elsewhere
# sealed-lane + courier-kind files: create blank, fill when the feature is enabled
for f in server_sign_key server_online_cert hf_token cf_token cf_kv_token bing_api_key wal_pub; do
  : > "$f.txt"
done
```

Rotation: `pg_password` cannot be rotated by just editing the file once the database exists
(`ALTER USER cx PASSWORD '...'` first, then edit, then `docker compose up -d`). The others can be
changed with a `docker compose up -d --force-recreate <service>`. Changing `server_secret`
invalidates outstanding PoW challenges only (10 min), never tokens.
