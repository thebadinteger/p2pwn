//go:build windows
// +build windows

package core

import (
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
	procGetStdHandle   = kernel32.NewProc("GetStdHandle")
)

const (
	stdOutputHandle                 = uint32(0xFFFFFFF5) // (DWORD)-11
	stdErrorHandle                  = uint32(0xFFFFFFF4) // (DWORD)-12
	enableVirtualTerminalProcessing = uint32(0x0004)
)

func InitConsole() {
	for _, stdHandleID := range []uint32{stdOutputHandle, stdErrorHandle} {
		handle, _, _ := procGetStdHandle.Call(uintptr(stdHandleID))
		if handle == 0 || handle == uintptr(syscall.InvalidHandle) {
			continue
		}
		var mode uint32
		r, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
		if r != 0 {
			procSetConsoleMode.Call(handle, uintptr(mode|enableVirtualTerminalProcessing))
		}
	}
}
