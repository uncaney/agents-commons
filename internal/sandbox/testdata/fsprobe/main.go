// fsprobe: lists / and /lib (name size kind modtime), reads a file N times and tries a write.
// stdin: "<path> [repeat]". Built with build.sh into ../fsprobe.wasm (GOOS=wasip1).
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func main() {
	in, _ := io.ReadAll(os.Stdin)
	f := strings.Fields(string(in))
	path, repeat := "/etc/passwd", 1
	if len(f) > 0 {
		path = f[0]
	}
	if len(f) > 1 {
		repeat, _ = strconv.Atoi(f[1])
	}
	for _, d := range []string{"/", "/lib"} {
		es, err := os.ReadDir(d)
		if err != nil {
			fmt.Printf("ls %s: %v\n", d, err)
			continue
		}
		for _, e := range es {
			fi, err := e.Info()
			if err != nil {
				fmt.Printf("ls %s/%s: %v\n", d, e.Name(), err)
				continue
			}
			kind := "f"
			if fi.IsDir() {
				kind = "d"
			}
			fmt.Printf("%s %s %d %s %d\n", d, e.Name(), fi.Size(), kind, fi.ModTime().Unix())
		}
	}
	total := 0
	var head []byte
	for i := 0; i < repeat; i++ {
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("read %s: %v\n", path, err)
			os.Exit(2)
		}
		total += len(b)
		if i == 0 && len(b) > 16 {
			b = b[:16]
		}
		if i == 0 {
			head = b
		}
	}
	fmt.Printf("read %s x%d total=%d head=%q\n", path, repeat, total, head)
	if err := os.WriteFile("/lib/new", []byte("x"), 0o644); err != nil {
		fmt.Println("write error:", err)
	} else {
		fmt.Println("wrote /lib/new")
		os.Exit(3)
	}
}
