// loop: never terminates.
package main

func main() {
	var x uint64
	for {
		x++
		if x == 0 {
			println("wrap")
		}
	}
}
