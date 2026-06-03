package main

import "github.com/rjcuff/pqctl/cmd"

var version = "dev"

func main() {
	cmd.SetVersion(version)
	cmd.Execute()
}
