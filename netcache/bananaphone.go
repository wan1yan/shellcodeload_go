package Applephone

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

// ApplePhone resolves SysID's by manually parsing the export table of ntdll.dll
// read from a suspended process.
type ApplePhone struct {
	ntdllBytes []byte
}

// NewApplePhone creates a new instance of an ApplePhone by creating a suspended process
// and reading its clean copy of ntdll.dll from memory.
func NewApplePhone() (*ApplePhone, error) {
	bp := &ApplePhone{}

	// 1. Create a sacrificial process in a suspended state
	cmd, err := syscall.UTF16PtrFromString("c:\\windows\\system32\\svchost.exe")
	if err != nil {
		return nil, fmt.Errorf("failed to create UTF16 pointer for command: %v", err)
	}

	si := new(STARTUPINFO)
	pi := new(PROCESS_INFORMATION)
	si.Cb = uint32(unsafe.Sizeof(*si))

	ret, _, err := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(cmd)),
		0, 0, 0, 0,
		CREATE_SUSPENDED,
		0, 0,
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(pi)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CreateProcessW failed: %v", err)
	}

	// Clean up the process handles on exit
	defer procCloseHandle.Call(uintptr(pi.hProcess))
	defer procCloseHandle.Call(uintptr(pi.hThread))
	defer procTerminateProcess.Call(uintptr(pi.hProcess), 0)

	// 2. Get the thread context to find the PEB address
	ctx := &CONTEXT{}
	ctx.ContextFlags = CONTEXT_FULL_AMD64

	if ret, _, _ := procGetThreadContext.Call(uintptr(pi.hThread), uintptr(unsafe.Pointer(ctx))); ret == 0 {
		return nil, fmt.Errorf("GetThreadContext failed")
	}

	// The PEB address is in the Rdx register for the main thread of a new process on amd64
	// pebAddress := ctx.Rdx

	// 3. Locate ntdll.dll base address
	ntdllH, _ := syscall.LoadLibrary("ntdll.dll")
	ntdllBaseAddr := uintptr(ntdllH)

	// 4. Read the ntdll.dll header (1KB is enough to find SizeOfImage)
	headerBuf := make([]byte, 1024)
	var bytesRead uintptr
	ret, _, err = procReadProcessMemory.Call(
		uintptr(pi.hProcess),
		ntdllBaseAddr,
		uintptr(unsafe.Pointer(&headerBuf[0])),
		uintptr(len(headerBuf)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("ReadProcessMemory for ntdll header failed: %v", err)
	}

	// 5. Manually parse the SizeOfImage from the PE header
	e_lfanew := binary.LittleEndian.Uint32(headerBuf[0x3C:0x40])
	sizeOfImageOffset := e_lfanew + 0x18 + 0x38
	sizeOfImage := binary.LittleEndian.Uint32(headerBuf[sizeOfImageOffset : sizeOfImageOffset+4])

	// 6. Read the ENTIRE ntdll image from the sacrificial process
	bp.ntdllBytes = make([]byte, sizeOfImage)
	ret, _, err = procReadProcessMemory.Call(
		uintptr(pi.hProcess),
		ntdllBaseAddr,
		uintptr(unsafe.Pointer(&bp.ntdllBytes[0])),
		uintptr(sizeOfImage),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("ReadProcessMemory for full ntdll failed: %v", err)
	}

	// 7. Terminate sacrificial process
	procTerminateProcess.Call(uintptr(pi.hProcess), 0)

	return bp, nil
}

// GetSysID resolves the provided function name into a sysid by manually parsing
// the export table in the ntdllBytes.
func (b *ApplePhone) GetSysID(funcName string) (uint16, error) {

	// 1. Manually find Export Directory RVA
	e_lfanew := binary.LittleEndian.Uint32(b.ntdllBytes[0x3C:0x40])
	exportDirectoryRvaOffset := e_lfanew + 0x18 + 0x70 // OptionalHeader.DataDirectory[0].VirtualAddress
	exportDirectoryRva := binary.LittleEndian.Uint32(b.ntdllBytes[exportDirectoryRvaOffset : exportDirectoryRvaOffset+4])

	if exportDirectoryRva == 0 {
		return 0, fmt.Errorf("could not find export directory RVA")
	}

	// 2. Parse IMAGE_EXPORT_DIRECTORY
	numberOfNames := binary.LittleEndian.Uint32(b.ntdllBytes[exportDirectoryRva+0x18 : exportDirectoryRva+0x18+4])
	addressOfFunctions := binary.LittleEndian.Uint32(b.ntdllBytes[exportDirectoryRva+0x1C : exportDirectoryRva+0x1C+4])
	addressOfNames := binary.LittleEndian.Uint32(b.ntdllBytes[exportDirectoryRva+0x20 : exportDirectoryRva+0x20+4])
	addressOfNameOrdinals := binary.LittleEndian.Uint32(b.ntdllBytes[exportDirectoryRva+0x24 : exportDirectoryRva+0x24+4])

	for i := uint32(0); i < numberOfNames; i++ {
		nameRva := binary.LittleEndian.Uint32(b.ntdllBytes[addressOfNames+i*4 : addressOfNames+i*4+4])

		// Extract name string
		var n int
		for n = 0; b.ntdllBytes[nameRva+uint32(n)] != 0; n++ {
		}
		name := string(b.ntdllBytes[nameRva : nameRva+uint32(n)])

		if name == funcName {
			ordinal := binary.LittleEndian.Uint16(b.ntdllBytes[addressOfNameOrdinals+i*2 : addressOfNameOrdinals+i*2+2])
			funcRva := binary.LittleEndian.Uint32(b.ntdllBytes[addressOfFunctions+uint32(ordinal)*4 : addressOfFunctions+uint32(ordinal)*4+4])

			// Read the function prologue to get the SSN
			funcBytes := b.ntdllBytes[funcRva : funcRva+10]
			sysID, err := sysIDFromRawBytes(funcBytes)
			if err == nil {
				return sysID, nil
			}
			return 0, err
		}
	}

	return 0, fmt.Errorf("could not find syscall ID for function: %s", funcName)
}

// MayBeHookedError an error returned when trying to extract the sysid from a resolved function.
type MayBeHookedError struct {
	Foundbytes []byte
}

func (e MayBeHookedError) Error() string {
	return fmt.Sprintf("may be hooked: wanted %x got %x", HookCheck, e.Foundbytes)
}

// HookCheck is the bytes expected to be seen at the start of the function
var HookCheck = []byte{0x4c, 0x8b, 0xd1, 0xb8}
