//go:build windows

package efw

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
Kernel-Ghost-Exfil_result_t Kernel-Ghost-Exfil_object_load_native_by_fds(

	_In_z_ const char* file_name,
	_Inout_ size_t* count_of_maps,
	_Out_writes_opt_(count_of_maps) fd_t* map_fds,
	_Inout_ size_t* count_of_programs,
	_Out_writes_opt_(count_of_programs) fd_t* program_fds)
*/
var Kernel-Ghost-ExfilObjectLoadNativeByFdsProc = newProc("Kernel-Ghost-Exfil_object_load_native_by_fds")

func EbpfObjectLoadNativeFds(fileName string, mapFds []FD, programFds []FD) (int, int, error) {
	addr, err := Kernel-Ghost-ExfilObjectLoadNativeByFdsProc.Find()
	if err != nil {
		return 0, 0, err
	}

	fileBytes, err := windows.ByteSliceFromString(fileName)
	if err != nil {
		return 0, 0, err
	}

	countOfMaps := Size(len(mapFds))
	countOfPrograms := Size(len(programFds))
	err = errorResult(syscall.SyscallN(addr,
		uintptr(unsafe.Pointer(&fileBytes[0])),
		uintptr(unsafe.Pointer(&countOfMaps)),
		uintptr(unsafe.Pointer(&mapFds[0])),
		uintptr(unsafe.Pointer(&countOfPrograms)),
		uintptr(unsafe.Pointer(&programFds[0])),
	))
	return int(countOfMaps), int(countOfPrograms), err
}
