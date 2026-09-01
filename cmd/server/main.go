package main

import (
	"os"

	"azugo.io/core/cli"
)

// Version is set at build time.
var Version = "0.1.0-dev"

func main() {
	if _, ok := os.LookupEnv("SERVER_URLS"); !ok {
		_ = os.Setenv("SERVER_URLS", "http://0.0.0.0:8080")
	}

	cli.Run(cli.Options{
		Use:     "eparaksts-signer",
		Short:   "eParaksts Signing Service",
		Long:    "Unified signing provider over the eParaksts/Entrust family (CSC + TrustedX) and the local eID card. Starts the web server by default.",
		Version: Version,
	})
}
