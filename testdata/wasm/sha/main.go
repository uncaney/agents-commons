// sha: prints sha256 hex of stdin.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

func main() {
	h := sha256.New()
	io.Copy(h, os.Stdin)
	os.Stdout.WriteString(hex.EncodeToString(h.Sum(nil)) + "\n")
}
