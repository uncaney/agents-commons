//go:build ignore

// keygen.go — generate the WAL archive X25519 keypair on the operator box (P121, SPEC-v2 27.9).
//
//	go run deploy/wal/keygen.go
//
// It prints the PRIVATE key (keep it OFF the server, e.g. in the vault) and the PUBLIC key. Only the
// public key becomes the courier secret:
//
//	go run deploy/wal/keygen.go
//	# store the private line in the vault; write the public line to deploy/secrets/wal_pub.txt
//
// Nothing is written to disk by this tool; redirect what you need yourself.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	pub := priv.PublicKey().Bytes()
	fmt.Printf("# WAL archive keypair (X25519) — generated %s\n", "on the operator box")
	fmt.Printf("WAL_PRIVATE_KEY_HEX  %s   # SECRET: store in the vault, never on the server\n", hex.EncodeToString(priv.Bytes()))
	fmt.Printf("WAL_PUBLIC_KEY_HEX   %s   # -> deploy/secrets/wal_pub.txt (courier secret wal_pub)\n", hex.EncodeToString(pub))
	fmt.Printf("WAL_PUBLIC_KEY_B64   %s\n", base64.StdEncoding.EncodeToString(pub))
}
