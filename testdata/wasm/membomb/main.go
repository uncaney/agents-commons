// membomb: allocates 1 MiB chunks until the runtime dies.
package main

var keep [][]byte

func main() {
	for {
		b := make([]byte, 1<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		keep = append(keep, b)
	}
}
