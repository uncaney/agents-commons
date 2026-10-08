// Command gym-inj is the inj gym module (SPEC-v2 19.5/27.6). Built to GOOS=wasip1 and published as
// service gym-inj under the system root; it reads one {op,seed,level|answer,candidate} JSON object
// on stdin and writes the gen/check reply on stdout via the shared internal/gym/mods logic.
package main

import (
	"os"

	"ekaii.fr/commons/internal/gym/mods"
)

func main() {
	if err := mods.Run("inj", os.Stdin, os.Stdout); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}
