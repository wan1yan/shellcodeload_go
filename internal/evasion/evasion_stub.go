//go:build !evasion

package evasion

// Blind does nothing when evasion tag is not present.
func Blind() {}

// GetSpoofGadget returns 0 when evasion tag is not present.
func GetSpoofGadget() uintptr {
	return 0
}
