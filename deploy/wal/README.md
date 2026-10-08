# Continuous WAL archiving + PITR restore drill (P121, SPEC-v2 27.9)

The courier's `wal_ship` scanner continuously archives Postgres WAL off-box, **encrypted**, so the
commons can be restored to any point in time even though the production server holds no decryption key
and no bucket read token. This directory is the operator's half of that feature.

```
deploy/wal/
├── compose.wal.yml   overlay: archive_mode, the shared walspool volume, the weekly basebackup sidecar
├── keygen.go         generate the X25519 keypair on the operator box (go run)
├── decrypt.go        reverse the courier's ECIES with the private key (go run; used by the drill)
├── walfetch.sh       Postgres restore_command: decrypt one WAL segment from the local mirror
└── restore-pitr.sh   the restore drill: mirror → decrypt → replay → smoke queries → Kuma
```

## How it works

1. Postgres runs with `archive_mode=on` and
   `archive_command='test ! -f /wal/%f && cp %p /wal/%f'`, copying each completed segment onto the
   shared `walspool` volume (`/wal`). `archive_timeout=60` bounds the RPO on an idle cluster.
2. The courier (kind `wal_ship`, a 60 s scanner with no outbox rows) lists `/wal`, seals each segment
   with stdlib ECIES to the operator's **public** key (ephemeral X25519 → HKDF-SHA256 → AES-256-GCM,
   wire = `ephemeral_pub(32) || nonce(12) || ciphertext+tag`, AAD = the object key), PUTs it to the
   backup bucket under `wal/<f>` with the P41 SigV4 signer (write-only policy), and deletes the local
   copy after a `200`. The weekly `pg_basebackup` sidecar writes `basebackup/base-<ts>.tgz`, shipped
   the same way under `basebackup/<f>`.
3. Spool watermarks ride a status item the scanner POSTs to the gateway each tick
   (`POST /internal/wal/status`, dispatched to `egress.ResultFn["wal_ship"]`): at **50 %** it flags an
   operator-inbox event (`wal-spool`), at **90 %** it asks the gateway to raise `freeze:write`
   (`err frozen wal`) until the spool drains below 80 %, and it always carries
   `wal_last_archived_age_s` for the ops `/metrics` gauge.

The courier never holds the private key, and the server never holds a bucket **read** token — only the
operator box, during a drill, has either.

## One-time key generation (operator box)

```sh
go run deploy/wal/keygen.go
# WAL_PRIVATE_KEY_HEX  <64 hex>   # SECRET — store in the vault, NEVER on the server
# WAL_PUBLIC_KEY_HEX   <64 hex>
# WAL_PUBLIC_KEY_B64   <base64>
```

Put the **private** line in the vault (it is the only thing that can decrypt the archive). Write the
**public** key to the courier secret:

```sh
printf '%s\n' '<WAL_PUBLIC_KEY_HEX>' > deploy/secrets/wal_pub.txt
```

`wal_pub` accepts the key as hex or base64 (standard or URL, padded or not). Leave `wal_pub.txt` empty
to keep the kind off.

## Enable archiving

Fill the courier's S3 settings (shared with `backup_ship`): `S3_ENDPOINT`, `S3_BUCKET` and the
`s3_key` secret (a **write-only** bucket credential). Then bring the stack up with the overlay:

```sh
docker compose -f deploy/compose.yml -f deploy/wal/compose.wal.yml up -d
```

`walspool` must be writable by three uids — Postgres (writes), the basebackup sidecar (writes) and the
courier `65532` (reads + deletes). Give it a 2 GiB host quota like `pgdata`, and make the mount shared,
e.g. once after first `up`:

```sh
docker compose -f deploy/compose.yml -f deploy/wal/compose.wal.yml exec -u 0 postgres \
  sh -c 'chown 70:65532 /wal && chmod 2775 /wal && mkdir -p /wal/basebackup && chown 70:65532 /wal/basebackup && chmod 2775 /wal/basebackup'
```

(Set `WAL_SPOOL_BYTES` in the overlay to match the host quota so the 90 % freeze lands before the disk
does.)

## Restore drill (operator box)

Export read credentials for the bucket (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION`,
or an `aws` profile), then:

```sh
# full point-in-time restore of the latest basebackup + WAL up to a timestamp
deploy/wal/restore-pitr.sh \
  --privkey ~/vault/wal_priv.hex \
  --bucket  commons-wal \
  --endpoint https://s3.example.net \
  --pitr '2026-10-07 12:00:00+00' \
  --kuma  https://kuma.example/api/push/<token>

# or reuse an already-mirrored directory with no bucket access at all
deploy/wal/restore-pitr.sh --privkey ~/vault/wal_priv.hex --mirror ./wal-mirror --skip-sync
```

The drill mirrors `wal/` and `basebackup/` locally, decrypts the newest base backup with the private
key, unpacks it into a throwaway data directory, replays the archived WAL (each segment decrypted
on the fly by `walfetch.sh`) to the requested point in time, promotes the cluster, renames the
recovered database to `commons_drill`, runs the **10 smoke queries** and pushes the Kuma heartbeat
(`up` on success, `down` on any failure). It never touches production; pass `--keep` to inspect the
recovered cluster instead of deleting it.

Run it on a schedule (weekly) so a backup that cannot be restored is discovered before it is needed.
