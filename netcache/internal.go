package Applephone

import (
	"bytes"
	"syscall"
	"unsafe"
	
	"github.com/Binject/debug/pe"
	"golang.org/x/sys/windows"
)

// Add necessary syscalls from ntdll and kernel32
var (
	ntdll                    = syscall.NewLazyDLL("ntdll.dll")
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procRtlInitUnicodeString = ntdll.NewProc("RtlInitUnicodeString")
	procNtOpenSection        = ntdll.NewProc("NtOpenSection")
	procNtMapViewOfSection   = ntdll.NewProc("NtMapViewOfSection")
	procNtUnmapViewOfSection = ntdll.NewProc("NtUnmapViewOfSection")
	procCreateProcessW       = kernel32.NewProc("CreateProcessW")
	procReadProcessMemory    = kernel32.NewProc("ReadProcessMemory")
	procTerminateProcess     = kernel32.NewProc("TerminateProcess")
	procCloseHandle          = kernel32.NewProc("CloseHandle")
	procGetThreadContext     = kernel32.NewProc("GetThreadContext")
)

const (
	SECTION_MAP_READ   = 0x0004
	CREATE_SUSPENDED   = 0x00000004
	CONTEXT_FULL_AMD64 = 0x10000b
)

// UNICODE_STRING is a structure that is used by the Windows kernel to represent a Unicode string.
type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

// OBJECT_ATTRIBUTES is used to specify the attributes of an object that is being created or opened.
type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *UNICODE_STRING
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// STARTUPINFO specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.
type STARTUPINFO struct {
	Cb              uint32
	lpReserved      *uint16
	lpDesktop       *uint16
	lpTitle         *uint16
	DwX             uint32
	DwY             uint32
	DwXSize         uint32
	DwYSize         uint32
	DwXCountChars   uint32
	DwYCountChars   uint32
	DwFillAttribute uint32
	DwFlags         uint32
	wShowWindow     uint16
	cbReserved2     uint16
	lpReserved2     *byte
	hStdInput       syscall.Handle
	hStdOutput      syscall.Handle
	hStdError       syscall.Handle
}

// PROCESS_INFORMATION contains information about a newly created process and its primary thread.
type PROCESS_INFORMATION struct {
	hProcess    syscall.Handle
	hThread     syscall.Handle
	dwProcessId uint32
	dwThreadId  uint32
}

// CONTEXT struct for amd64, this is the full structure needed for GetThreadContext
type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FltSave              [512]byte
	VectorRegister       [26]uint64
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

// RtlInitUnicodeString initializes a UNICODE_STRING structure.
func RtlInitUnicodeString(target *UNICODE_STRING, source string) {
	sourcePtr, _ := syscall.UTF16PtrFromString(source)
	procRtlInitUnicodeString.Call(
		uintptr(unsafe.Pointer(target)),
		uintptr(unsafe.Pointer(sourcePtr)),
	)
}

//rvaToOffset converts an RVA value from a PE file into the file offset.
func rvaToOffset(pefile *pe.File, rva uint32) uint32 {
	for _, hdr := range pefile.Sections {
		baseoffset := uint64(rva)
		if baseoffset > uint64(hdr.VirtualAddress) &&
			baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
			return rva - hdr.VirtualAddress + hdr.Offset
		}
	}
	return rva
}

//sysIDFromRawBytes takes a byte slice and determines if there is a sysID in the expected location. Returns a MayBeHookedError if the signature does not match.
func sysIDFromRawBytes(b []byte) (uint16, error) {
	if !bytes.HasPrefix(b, HookCheck) {
		return 0, MayBeHookedError{Foundbytes: b}
	}
	// Note: binary package should ideally be used, but since we are fixing a build error,
	// let's use a simple manual extraction to avoid unnecessary imports if they are unused elsewhere.
	return uint16(b[4]) | uint16(b[5])<<8, nil
}

//stupidstring is the stupid internal windows definiton of a unicode string. I hate it.
type stupidstring struct {
	Length    uint16
	MaxLength uint16
	PWstr     *uint16
}

func (s stupidstring) String() string {
	return windows.UTF16PtrToString(s.PWstr)
}
