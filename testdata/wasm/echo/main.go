// echo: stdin -> stdout, uppercased.
package main

import (
	"bytes"
	"io"
	"os"
)

func main() {
	b, _ := io.ReadAll(os.Stdin)
	os.Stdout.Write(bytes.ToUpper(b))
}
