#!/bin/sh
# walfetch.sh — Postgres restore_command for the P121 restore drill (SPEC-v2 27.9).
#
# Postgres calls this with the segment name (%f) and the destination path (%p), from the data
# directory. The encrypted segment lives in the LOCAL MIRROR at $WAL_MIRROR/wal/<f> (the verbatim
# bucket object, ECIES ciphertext); we decrypt it with the prebuilt tool and the private key, which
# exists only on the operator box. Exit non-zero when the segment is absent — Postgres reads that as
# the end of the archive and finishes recovery.
set -eu

f="${1:?usage: walfetch.sh %f %p}"
dest="${2:?usage: walfetch.sh %f %p}"

: "${WAL_MIRROR:?WAL_MIRROR not set}"
: "${WAL_DECRYPT_BIN:?WAL_DECRYPT_BIN not set}"
: "${WAL_PRIVKEY:?WAL_PRIVKEY not set}"

src="$WAL_MIRROR/wal/$f"
[ -f "$src" ] || exit 1

# aad binds the ciphertext to the exact object key it was uploaded under (wal/<f>).
exec "$WAL_DECRYPT_BIN" -key "$WAL_PRIVKEY" -aad "wal/$f" -in "$src" -out "$dest"
