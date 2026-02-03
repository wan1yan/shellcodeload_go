//go:build !sandbox

package check

// RunSystemAudit 在非沙箱模式下直接返回 true
func RunSystemAudit() bool {
	return true
}

// ShowWarning 在非沙箱模式下不执行任何操作
func ShowWarning() {
}

// EnvironmentChecksPass performs basic anti-sandbox checks.
// In !sandbox mode, it always returns true.
func EnvironmentChecksPass() bool {
	return true
}
