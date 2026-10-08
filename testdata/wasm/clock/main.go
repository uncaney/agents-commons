// clock: prints wall clock, monotonic delta and crypto/rand bytes; must be identical across runs.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

func main() {
	t0 := time.Now()
	time.Sleep(10 * time.Millisecond)
	t1 := time.Now()
	var b [16]byte
	rand.Read(b[:])
	fmt.Println(t0.UnixNano(), t1.Sub(t0).Nanoseconds(), hex.EncodeToString(b[:]))
}
