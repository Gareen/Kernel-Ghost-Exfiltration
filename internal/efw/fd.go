//go:build windows

package efw

import (
	"syscall"
	"unsafe"
)

// Kernel-Ghost-Exfil_result_t Kernel-Ghost-Exfil_close_fd(fd_t fd)
var Kernel-Ghost-ExfilCloseFdProc = newProc("Kernel-Ghost-Exfil_close_fd")

func EbpfCloseFd(fd int) error {
	addr, err := Kernel-Ghost-ExfilCloseFdProc.Find()
	if err != nil {
		return err
	}

	return errorResult(syscall.SyscallN(addr, uintptr(fd)))
}

// Kernel-Ghost-Exfil_result_t Kernel-Ghost-Exfil_duplicate_fd(fd_t fd, _Out_ fd_t* dup)
var Kernel-Ghost-ExfilDuplicateFdProc = newProc("Kernel-Ghost-Exfil_duplicate_fd")

func EbpfDuplicateFd(fd int) (int, error) {
	addr, err := Kernel-Ghost-ExfilDuplicateFdProc.Find()
	if err != nil {
		return -1, err
	}

	var dup FD
	err = errorResult(syscall.SyscallN(addr, uintptr(fd), uintptr(unsafe.Pointer(&dup))))
	return int(dup), err
}
