//go:build !debug

package log

// Info does nothing in release mode.
func Info(format string, args ...any) {}

// Success does nothing in release mode.
func Success(format string, args ...any) {}

// Error does nothing in release mode.
func Error(format string, args ...any) {}

// Debugf does nothing in release mode.
func Debugf(format string, args ...any) {}
