package main

import (
	"azugo.io/azugo/server"
	"azugo.io/core/cli"

	app "github.com/signbyte/eparaksts-signer"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "eParaksts Signing Service",
		AppVer:        Version,
		Configuration: app.NewConfiguration(),
	}))
}
