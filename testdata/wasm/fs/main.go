// fs: tries to read and write files (no preopens in the sandbox).
package main

import (
	"fmt"
	"os"
)

func main() {
	rc := 0
	if b, err := os.ReadFile("/etc/passwd"); err != nil {
		fmt.Println("read error:", err)
	} else {
		fmt.Printf("read %d bytes\n", len(b))
		rc |= 1
	}
	if err := os.WriteFile("/tmp/x", []byte("x"), 0o644); err != nil {
		fmt.Println("write error:", err)
	} else {
		fmt.Println("wrote /tmp/x")
		rc |= 2
	}
	os.Exit(rc)
}
