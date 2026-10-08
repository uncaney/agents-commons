// net: tries to open a TCP connection (no sockets in wasip1).
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	c, err := net.Dial("tcp", "1.1.1.1:80")
	if err != nil {
		fmt.Println("dial error:", err)
		os.Exit(1)
	}
	c.Close()
	fmt.Println("connected")
}
