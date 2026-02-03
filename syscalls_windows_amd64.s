#include "textflag.h"

// func SyscallJump(ssn uint16, gadget uintptr, a1, a2, a3, a4, a5, a6 uintptr, spoofAddr uintptr) uintptr
TEXT ·SyscallJump(SB), NOSPLIT, $0-80
    XORQ AX, AX
    MOVW ssn+0(FP), AX
    MOVQ gadget+8(FP), R11

    MOVQ a1+16(FP), R10
    MOVQ a2+24(FP), DX
    MOVQ a3+32(FP), R8
    MOVQ a4+40(FP), R9

    MOVQ a5+48(FP), R12
    MOVQ a6+56(FP), R13
    
    MOVQ spoofAddr+64(FP), R15

    TESTQ R15, R15
    JNZ spoof_call

    // --- Normal Path ---
    SUBQ $56, SP
    MOVQ R12, 32(SP)
    MOVQ R13, 40(SP)
    CALL R11
    ADDQ $56, SP
    MOVQ AX, ret+72(FP)
    RET

spoof_call:
    // --- Spoof Path ---
    SUBQ $64, SP
    MOVQ R15, 0(SP)         // Fake Return Address
    
    // CALL next instruction (E8 00 00 00 00)
    BYTE $0xE8; BYTE $0x00; BYTE $0x00; BYTE $0x00; BYTE $0x00
    // POP BX (5B)
    BYTE $0x5B
    
    // ADDQ $23, BX (48 83 C3 17)
    BYTE $0x48; BYTE $0x83; BYTE $0xC3; BYTE $0x17
    
    MOVQ BX, 8(SP)          // Real Return Address
    
    MOVQ R12, 40(SP)        // P5
    MOVQ R13, 48(SP)        // P6
    
    JMP R11

return_here:
    // Stack was popped twice (SpoofAddr, RealRet) = 16 bytes.
    // 64 - 16 = 48 bytes to restore.
    ADDQ $48, SP
    MOVQ AX, ret+72(FP)
    RET
