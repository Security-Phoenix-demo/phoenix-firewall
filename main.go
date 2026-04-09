// Package main is the entry point for the Phoenix Security Supply Chain Firewall proxy.
// It delegates all CLI handling to the cmd package.
package main

import "github.com/nicokoenig/phoenix-firewall/cmd"

func main() {
	cmd.Execute()
}
