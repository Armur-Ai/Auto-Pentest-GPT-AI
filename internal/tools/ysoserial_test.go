package tools

import "testing"

// TestYsoserialTool_Name — adapter id matches the plan and the binary.
func TestYsoserialTool_Name(t *testing.T) {
	if n := NewYsoserialTool().Name(); n != "ysoserial" {
		t.Errorf("Name() = %q, want \"ysoserial\"", n)
	}
}

func TestYsoserialTool_IsAvailable(t *testing.T) {
	_ = NewYsoserialTool().IsAvailable()
}
