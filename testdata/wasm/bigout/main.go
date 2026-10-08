// bigout: writes 20 MiB to stdout (exceeds the 16 MiB cap).
package main

import "os"

func main() {
	buf := make([]byte, 1<<20)
	for i := range buf {
		buf[i] = 'a'
	}
	for i := 0; i < 20; i++ {
		os.Stdout.Write(buf)
	}
}
