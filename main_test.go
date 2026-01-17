package main

import (
	"net"
	"testing"
)

func TestParseCIDRs(t *testing.T) {
	tests := []struct {
		input    string
		expected int
		wantErr  bool
	}{
		{"", 0, false},
		{"192.168.1.0/24", 1, false},
		{"192.168.1.0/24, 10.0.0.0/8", 2, false},
		{"invalid", 0, true},
		{"192.168.1.0/24, invalid", 0, true},
	}

	for _, tt := range tests {
		result, err := parseCIDRs(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseCIDRs(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if len(result) != tt.expected {
			t.Errorf("parseCIDRs(%q) returned %d subnets, expected %d", tt.input, len(result), tt.expected)
		}
	}
}

func TestSubnetCheck(t *testing.T) {
    // Test the logic used in resolveUpstream
    subnets, _ := parseCIDRs("192.168.1.0/24, 10.0.0.0/8")
    
    allow := func(ipStr string) bool {
        ip := net.ParseIP(ipStr)
        for _, s := range subnets {
            if s.Contains(ip) {
                return true
            }
        }
        return false
    }

    if !allow("192.168.1.50") {
        t.Error("Should allow 192.168.1.50")
    }
    if !allow("10.5.5.5") {
        t.Error("Should allow 10.5.5.5")
    }
    if allow("8.8.8.8") {
        t.Error("Should not allow 8.8.8.8")
    }
}
