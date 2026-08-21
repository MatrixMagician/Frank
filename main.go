package main

import (
	"os"

	"github.com/MatrixMagician/Frank/internal/cli"
)

func main() {
	code := cli.Main(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(int(code))
}
