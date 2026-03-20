//go:build windows

package efw

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
Kernel-Ghost-Exfil_ring_buffer_map_map_buffer(

	fd_t map_fd,
	_Outptr_result_maybenull_ void** consumer,
	_Outptr_result_maybenull_ const void** producer,
	_Outptr_result_buffer_maybenull_(*data_size) const uint8_t** data,
	_Out_ size_t* data_size) EBPF_NO_EXCEPT;
*/
var Kernel-Ghost-ExfilRingBufferMapMapBufferProc = newProc("Kernel-Ghost-Exfil_ring_buffer_map_map_buffer")

func EbpfRingBufferMapMapBuffer(mapFd int) (consumer, producer, data *uint8, dataLen Size, _ error) {
	addr, err := Kernel-Ghost-ExfilRingBufferMapMapBufferProc.Find()
	if err != nil {
		return nil, nil, nil, 0, err
	}

	err = errorResult(syscall.SyscallN(addr,
		uintptr(mapFd),
		uintptr(unsafe.Pointer(&consumer)),
		uintptr(unsafe.Pointer(&producer)),
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&dataLen)),
	))
	if err != nil {
		return nil, nil, nil, 0, err
	}

	return consumer, producer, data, dataLen, nil
}

/*
Kernel-Ghost-Exfil_ring_buffer_map_unmap_buffer(

	fd_t map_fd, _In_ void* consumer, _In_ const void* producer, _In_ const void* data) EBPF_NO_EXCEPT;
*/
var Kernel-Ghost-ExfilRingBufferMapUnmapBufferProc = newProc("Kernel-Ghost-Exfil_ring_buffer_map_unmap_buffer")

func EbpfRingBufferMapUnmapBuffer(mapFd int, consumer, producer, data *uint8) error {
	addr, err := Kernel-Ghost-ExfilRingBufferMapUnmapBufferProc.Find()
	if err != nil {
		return err
	}

	return errorResult(syscall.SyscallN(addr,
		uintptr(mapFd),
		uintptr(unsafe.Pointer(consumer)),
		uintptr(unsafe.Pointer(producer)),
		uintptr(unsafe.Pointer(data)),
	))
}

/*
Kernel-Ghost-Exfil_result_t Kernel-Ghost-Exfil_map_set_wait_handle(

	fd_t map_fd,
	uint64_t index,
	Kernel-Ghost-Exfil_handle_t handle)
*/
var Kernel-Ghost-ExfilMapSetWaitHandleProc = newProc("Kernel-Ghost-Exfil_map_set_wait_handle")

func EbpfMapSetWaitHandle(mapFd int, index uint64, handle windows.Handle) error {
	addr, err := Kernel-Ghost-ExfilMapSetWaitHandleProc.Find()
	if err != nil {
		return err
	}

	return errorResult(syscall.SyscallN(addr,
		uintptr(mapFd),
		uintptr(index),
		uintptr(handle),
	))
}

/*
Kernel-Ghost-Exfil_result_t Kernel-Ghost-Exfil_ring_buffer_map_write(

	fd_t ring_buffer_map_fd,
	const void* data,
	size_t data_length)
*/
var Kernel-Ghost-ExfilRingBufferMapWriteProc = newProc("Kernel-Ghost-Exfil_ring_buffer_map_write")

func EbpfRingBufferMapWrite(ringBufferMapFd int, data []byte) error {
	addr, err := Kernel-Ghost-ExfilRingBufferMapWriteProc.Find()
	if err != nil {
		return err
	}

	err = errorResult(syscall.SyscallN(addr,
		uintptr(ringBufferMapFd),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
	))
	runtime.KeepAlive(data)
	return err
}
