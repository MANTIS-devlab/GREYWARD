// No cgroup discovery is needed before this fixed Python exec.
//go:debug containermaxprocs=0
//go:debug updatemaxprocs=0

package main

import (
	"fmt"
	"os"
	"syscall"
)

const approvalScript = "/usr/lib/greyward-security-context/greyward_security_context/usbguard_session.py"

func validReference(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func main() {
	if len(os.Args) != 3 || !validReference(os.Args[1]) ||
		(os.Args[2] != "once" && os.Args[2] != "always") {
		fmt.Println(`{"ok":false,"state":"INVALID","detail":"Choose a current USB device and Trust once or Trust always."}`)
		os.Exit(2)
	}
	argv := []string{"python3", "-I", "-B", approvalScript, os.Args[1], os.Args[2]}
	if err := syscall.Exec("/usr/bin/python3", argv, os.Environ()); err != nil {
		fmt.Println(`{"ok":false,"state":"UNAVAILABLE","detail":"USB approval could not start. The device remains blocked."}`)
		os.Exit(126)
	}
}
