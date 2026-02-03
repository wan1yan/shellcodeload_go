// resolver.go
package main

import (
	"fmt"
	// 必须是: 模块名 + 路径
	// 假设你的 go.mod 里 module 是 codeload
	bp "codeload/netcache"
)

var AppleHandle *bp.ApplePhone

func initResolver() error {
	var err error
	// In v4, NewApplePhone has no arguments as it always uses the KnownDlls method.
	AppleHandle, err = bp.NewApplePhone()
	if err != nil {
		return fmt.Errorf("ApplePhone initialization failed: %w", err)
	}
	return nil
}

func getSSN(funcName string) uint16 {
	// GetSysID is the correct method name in the refactored bananaphone
	id, err := AppleHandle.GetSysID(funcName)
	if err != nil {
		// Log the error for debugging, but return 0 to the caller
		return 0
	}
	return id
}
