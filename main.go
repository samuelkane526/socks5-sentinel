package main

import (
	"fmt"
	"os"

	"github.com/samuelkane526/socks5-sentinel/internal/cli"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

func main() {
	if _, err := proxycore.EnsureDataDir(""); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to initialize data directory: %v\n", err)
	}
	os.Exit(cli.Run(os.Args[1:]))
}
