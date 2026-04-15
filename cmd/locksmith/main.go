package main

import (
	"github.com/bonjoski/locksmith/v2/cmd/locksmith/cmd"
)

var version string

func main() {
	cmd.Execute(version)
}
