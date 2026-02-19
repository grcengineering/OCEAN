package main

import (
	"os"

	"github.com/grcengineering/ocean/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
