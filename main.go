package main

import (
	"os"

	"github.com/moveeeax/prom-alert-lint/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
