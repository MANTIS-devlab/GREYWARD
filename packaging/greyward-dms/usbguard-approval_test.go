package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestValidReference(t *testing.T) {
	for _, reference := range []string{
		"0123456789abcdef0123456789abcdef",
		"abcdefabcdefabcdefabcdefabcdefab",
	} {
		if !validReference(reference) {
			t.Errorf("valid device reference rejected: %q", reference)
		}
	}
	for _, reference := range []string{
		"", "0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdefg",
		"0123456789abcdef0123456789abcdeG", "0123456789abcdef0123456789abcde/",
	} {
		if validReference(reference) {
			t.Errorf("invalid device reference accepted: %q", reference)
		}
	}
}

func TestIPCUsesPIDSelectionWithoutConflictingDisplaySelection(t *testing.T) {
	got := ipcArguments(152796, "authentication", "requestUsbTrust",
		"abcdefabcdefabcdefabcdefabcdefab", "always", "0123456789abcdef0123456789abcdef")
	want := []string{"ipc", "--pid", "152796", "call", "authentication", "requestUsbTrust",
		"abcdefabcdefabcdefabcdefabcdefab", "always", "0123456789abcdef0123456789abcdef"}
	if len(got) != len(want) {
		t.Fatalf("IPC arguments differ: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("IPC argument %d differs: got %v, want %v", i, got, want)
		}
	}
	for _, arg := range got {
		if arg == "--any-display" {
			t.Fatal("--any-display conflicts with --pid instance selection")
		}
	}
}

func TestParseReadinessRequiresFreshRegisteredProtectedAgent(t *testing.T) {
	now := time.Now()
	data := []byte(`{"schema":"greyward.authentication-readiness/v1","pid":152796,"observedAtMs":` +
		fmtInt(now.UnixMilli()) + `,"polkitRegistered":true,"polkitActive":false}`)
	pid, result := parseReadiness(data, now, now, 1000, 1000)
	if pid != 152796 || result.State != "" {
		t.Fatalf("fresh protected readiness rejected: pid=%d result=%+v", pid, result)
	}
	if pid, result = parseReadiness(data, now.Add(-6*time.Second), now, 1000, 1000); pid != 0 || result.State != "UNAVAILABLE" {
		t.Fatalf("stale readiness accepted: pid=%d result=%+v", pid, result)
	}
	busy := []byte(`{"schema":"greyward.authentication-readiness/v1","pid":152796,"observedAtMs":` +
		fmtInt(now.UnixMilli()) + `,"polkitRegistered":true,"polkitActive":true}`)
	if pid, result = parseReadiness(busy, now, now, 1000, 1000); pid != 0 || result.State != "BUSY" {
		t.Fatalf("active Polkit flow was not reported busy: pid=%d result=%+v", pid, result)
	}
	if pid, result = parseReadiness(data, now, now, 1000, 1001); pid != 0 || result.State != "UNAVAILABLE" {
		t.Fatalf("readiness owned by another UID was accepted: pid=%d result=%+v", pid, result)
	}
}

func TestDecodeIPCRequiresVerifiableState(t *testing.T) {
	if result, err := decodeIPCResult(`{"ok":true,"state":"COMPLETE","detail":"Trusted for future connections."}`); err != nil || !result.OK {
		t.Fatalf("verified completion rejected: result=%+v err=%v", result, err)
	}
	for _, invalid := range []string{
		"not-json",
		`{"ok":true}`,
		`{"ok":false,"state":"COMPLETE"}`,
		`{"ok":false,"state":"PENDING"}`,
	} {
		if _, err := decodeIPCResult(invalid); err == nil {
			t.Errorf("unverifiable or contradictory IPC result accepted: %s", invalid)
		}
	}
}

func TestWaitForApprovalRequiresProtectedSessionReadback(t *testing.T) {
	calls := 0
	call := func(_ context.Context, _ int, _ string, function string, args ...string) (string, error) {
		calls++
		if function == "requestUsbTrust" {
			if len(args) != 3 || args[1] != "always" || args[2] != "0123456789abcdef0123456789abcdef" {
				t.Fatalf("unexpected request args: %v", args)
			}
			return `{"ok":true,"state":"PENDING","detail":"Waiting for approval."}`, nil
		}
		if function != "usbTrustStatus" || len(args) != 1 || args[0] != "0123456789abcdef0123456789abcdef" {
			t.Fatalf("unexpected status call: %s %v", function, args)
		}
		return `{"ok":true,"state":"COMPLETE","detail":"USBGuard confirmed the persistent rule."}`, nil
	}
	result := waitForApproval(context.Background(), 152796,
		"abcdefabcdefabcdefabcdefabcdefab", "always",
		"0123456789abcdef0123456789abcdef", call, 0)
	if !result.OK || result.State != "COMPLETE" || calls != 2 {
		t.Fatalf("expected one request plus verified readback: result=%+v calls=%d", result, calls)
	}
}

func TestWaitForApprovalDoesNotPromoteExitOrTransportErrors(t *testing.T) {
	call := func(_ context.Context, _ int, _ string, _ string, _ ...string) (string, error) {
		return "", context.DeadlineExceeded
	}
	result := waitForApproval(context.Background(), 152796,
		"abcdefabcdefabcdefabcdefabcdefab", "once",
		"0123456789abcdef0123456789abcdef", call, 0)
	if result.OK || result.State != "UNAVAILABLE" {
		t.Fatalf("transport failure was reported as success: %+v", result)
	}
}

func fmtInt(value int64) string {
	return strconv.FormatInt(value, 10)
}

func TestReadinessFileRejectsUnsafeAndPartialRecords(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "authentication-ready.json")
	data := []byte(`{"schema":"greyward.authentication-readiness/v1","pid":152796,"observedAtMs":` +
		fmtInt(now.UnixMilli()) + `,"polkitRegistered":true,"polkitActive":false}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() >= 1000 {
		if pid, result := readReadinessFile(path, os.Getuid(), now); pid != 152796 || result.State != "" {
			t.Fatalf("private own-UID readiness rejected: %d %+v", pid, result)
		}
	}
	// Unit tests need not run as an enrolled desktop account.
	if pid, result := readReadinessFile(path, 1000, now); os.Getuid() != 1000 && (pid != 0 || result.State != "UNAVAILABLE") {
		t.Fatalf("another UID's record accepted: %d %+v", pid, result)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if pid, _ := readReadinessFile(link, os.Getuid(), now); pid != 0 {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if pid, _ := readReadinessFile(path, os.Getuid(), now); pid != 0 {
		t.Fatal("shared readiness accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".hardlink"); err != nil {
		t.Fatal(err)
	}
	if pid, _ := readReadinessFile(path, os.Getuid(), now); pid != 0 {
		t.Fatal("multiply linked readiness accepted")
	}
	for _, partial := range []string{"", `{"schema":`, `{"schema":"greyward.authentication-readiness/v1"}`} {
		if pid, _ := parseReadiness([]byte(partial), now, now, 1000, 1000); pid != 0 {
			t.Fatal("partial record accepted")
		}
	}
}
