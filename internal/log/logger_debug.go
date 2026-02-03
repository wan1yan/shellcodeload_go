//go:build debug

package log

import "fmt"

// Info logs general information with [*] prefix.
func Info(format string, args ...any) {
	fmt.Printf("[*] "+format+"\n", args...)
}

// Success logs successful operations with [+] prefix.
func Success(format string, args ...any) {
	fmt.Printf("[+] "+format+"\n", args...)
}

// Error logs error conditions with [-] prefix.
func Error(format string, args ...any) {
	fmt.Printf("[-] "+format+"\n", args...)
}

// Debugf logs debug details with [D] prefix.
func Debugf(format string, args ...any) {
	fmt.Printf("[D] "+format+"\n", args...)
}
