// exit3: writes a line then exits 3.
package main

import "os"

func main() {
	os.Stdout.WriteString("bye\n")
	os.Exit(3)
}
