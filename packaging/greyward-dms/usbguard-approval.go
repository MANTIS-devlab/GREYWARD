// These small IPC clients do not need container CPU discovery. Keep cgroup
// inspection denied instead of granting it for Go's default CPU autosizing.
//go:debug containermaxprocs=0
//go:debug updatemaxprocs=0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	requestTimeout = 140 * time.Second
	pollInterval   = 500 * time.Millisecond
	ipcTimeout     = 4 * time.Second
)

var connectionReference = regexp.MustCompile(`^[0-9a-f]{32}$`)

type readinessRecord struct {
	Schema           string `json:"schema"`
	PID              int    `json:"pid"`
	ObservedAtMs     int64  `json:"observedAtMs"`
	PolkitRegistered bool   `json:"polkitRegistered"`
	PolkitActive     bool   `json:"polkitActive"`
}

type approvalResult struct {
	OK     bool   `json:"ok"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

type ipcCaller func(context.Context, int, string, string, ...string) (string, error)

func ipcArguments(pid int, target, function string, args ...string) []string {
	argv := []string{"ipc", "--pid", strconv.Itoa(pid), "call", target, function}
	return append(argv, args...)
}

func validReference(value string) bool {
	return connectionReference.MatchString(value)
}

func parseReadiness(data []byte, modified time.Time, now time.Time, ownerUID, userUID int) (int, approvalResult) {
	failure := approvalResult{State: "UNAVAILABLE", Detail: "The protected authorization session is unavailable. The device remains blocked."}
	if userUID < 1000 || ownerUID != userUID || len(data) == 0 || len(data) > 4096 {
		return 0, failure
	}
	age := now.Sub(modified)
	if age < -2*time.Second || age > 5*time.Second {
		return 0, failure
	}
	var ready readinessRecord
	if err := json.Unmarshal(data, &ready); err != nil ||
		ready.Schema != "greyward.authentication-readiness/v1" ||
		ready.PID < 2 || ready.PID > 4_194_304 ||
		!ready.PolkitRegistered || ready.PolkitActive {
		if err == nil && ready.PolkitActive {
			return 0, approvalResult{State: "BUSY", Detail: "Another protected authorization is active. Try again when it finishes."}
		}
		return 0, failure
	}
	observedAge := now.UnixMilli() - ready.ObservedAtMs
	if observedAge < -2000 || observedAge > 5000 {
		return 0, failure
	}
	return ready.PID, approvalResult{}
}

func readReadiness(userUID int, now time.Time) (int, approvalResult) {
	runtime := filepath.Join("/run/greyward-application-security", "auth-"+strconv.Itoa(userUID), "runtime")
	path := filepath.Join(runtime, "usbguard-approval", "readiness.json")
	// An atomic replacement may unlink an already opened inode before fstat.
	// Retry fresh opens briefly; never accept a deleted or multiply linked file.
	for attempt := 0; ; attempt++ {
		pid, result := readReadinessFile(path, userUID, now)
		if result.State != "UNAVAILABLE" || attempt == 2 {
			return pid, result
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readReadinessFile(path string, userUID int, now time.Time) (int, approvalResult) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, approvalResult{State: "UNAVAILABLE", Detail: "The protected authorization session is unavailable. The device remains blocked."}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 0, approvalResult{State: "UNAVAILABLE", Detail: "The protected authorization session is unavailable. The device remains blocked."}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || info.Mode().Perm()&0077 != 0 {
		return 0, approvalResult{State: "UNAVAILABLE", Detail: "The protected authorization session is unavailable. The device remains blocked."}
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return 0, approvalResult{State: "UNAVAILABLE", Detail: "The protected authorization session is unavailable. The device remains blocked."}
	}
	return parseReadiness(data, info.ModTime(), now, int(stat.Uid), userUID)
}

func newRequestID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func runIPC(ctx context.Context, pid int, target, function string, args ...string) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, ipcTimeout)
	defer cancel()
	argv := ipcArguments(pid, target, function, args...)
	cmd := exec.CommandContext(callCtx, "/usr/bin/qs", argv...)
	uid := os.Getuid()
	runtime := filepath.Join("/run/greyward-application-security", "auth-"+strconv.Itoa(uid), "runtime")
	cmd.Env = []string{
		"PATH=/usr/bin:/usr/sbin",
		"HOME=" + filepath.Join(runtime, "..", "home"),
		"USER=" + os.Getenv("USER"),
		"LOGNAME=" + os.Getenv("LOGNAME"),
		"XDG_RUNTIME_DIR=" + runtime,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + filepath.Join(runtime, "bus"),
		"XDG_SESSION_TYPE=wayland",
		"WAYLAND_DISPLAY=wayland-0",
	}
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func decodeIPCResult(output string) (approvalResult, error) {
	var result approvalResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &result); err != nil || result.State == "" {
		return approvalResult{}, fmt.Errorf("invalid protected-session response")
	}
	if result.State == "COMPLETE" && !result.OK {
		return approvalResult{}, fmt.Errorf("completion did not include positive authorization evidence")
	}
	if result.State == "PENDING" && !result.OK {
		return approvalResult{}, fmt.Errorf("pending request was not accepted")
	}
	return result, nil
}

func waitForApproval(ctx context.Context, pid int, reference, mode, requestID string, call ipcCaller, interval time.Duration) approvalResult {
	initial, err := call(ctx, pid, "authentication", "requestUsbTrust", reference, mode, requestID)
	if err != nil {
		return approvalResult{State: "UNAVAILABLE", Detail: "The protected approval prompt could not be reached. The device remains blocked."}
	}
	result, err := decodeIPCResult(initial)
	if err != nil {
		return approvalResult{State: "FAILED", Detail: "The protected approval request returned no verifiable result. The device remains blocked."}
	}
	if result.State != "PENDING" {
		return result
	}
	deadline := time.Now().Add(requestTimeout)
	for time.Now().Before(deadline) {
		if interval > 0 {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return approvalResult{State: "CANCELLED", Detail: "The protected approval request was interrupted. Check the device state before retrying."}
			case <-timer.C:
			}
		}
		status, callErr := call(ctx, pid, "authentication", "usbTrustStatus", requestID)
		if callErr != nil {
			continue
		}
		result, err = decodeIPCResult(status)
		if err != nil {
			return approvalResult{State: "FAILED", Detail: "The protected approval result could not be verified. Check the device state before retrying."}
		}
		if result.State != "PENDING" {
			return result
		}
	}
	return approvalResult{State: "TIMEOUT", Detail: "No confirmed result arrived from the protected approval session. Check the device state before retrying."}
}

func emit(result approvalResult) {
	data, _ := json.Marshal(result)
	fmt.Println(string(data))
}

func main() {
	if len(os.Args) != 3 || !validReference(os.Args[1]) ||
		(os.Args[2] != "once" && os.Args[2] != "always") {
		emit(approvalResult{State: "INVALID", Detail: "Choose a current USB device and Trust once or Trust always."})
		os.Exit(2)
	}
	userUID := os.Getuid()
	pid, unavailable := readReadiness(userUID, time.Now())
	if unavailable.State != "" {
		emit(unavailable)
		os.Exit(1)
	}
	requestID, err := newRequestID()
	if err != nil {
		emit(approvalResult{State: "UNAVAILABLE", Detail: "A secure request ID could not be created. The device remains blocked."})
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout+10*time.Second)
	defer cancel()
	result := waitForApproval(ctx, pid, os.Args[1], os.Args[2], requestID, runIPC, pollInterval)
	emit(result)
	if !result.OK || result.State != "COMPLETE" {
		os.Exit(1)
	}
}
