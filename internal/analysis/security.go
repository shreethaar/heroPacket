package analysis

import (
	"heroPacket/internal/models"
	"sync"
)

type SecurityAnalyzer struct {
	mu              sync.Mutex
	SuspiciousPorts map[uint16]int // Port -> count
	ScanAttempts    map[string]int // IP -> scan count
	MaliciousIPs    map[string]int // IP -> suspicious activity count
}

func NewSecurityAnalyzer() *SecurityAnalyzer {
	return &SecurityAnalyzer{
		SuspiciousPorts: make(map[uint16]int),
		ScanAttempts:    make(map[string]int),
		MaliciousIPs:    make(map[string]int),
	}
}

func (s *SecurityAnalyzer) Process(packet models.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for common suspicious ports
	suspiciousPorts := map[uint16]bool{
		22:   true, // SSH
		23:   true, // Telnet
		3389: true, // RDP
		445:  true, // SMB
	}

	if suspiciousPorts[packet.SourcePort] {
		s.SuspiciousPorts[packet.SourcePort]++
	}
	if suspiciousPorts[packet.DestPort] {
		s.SuspiciousPorts[packet.DestPort]++
	}

	// Detect potential port scans
	// Implementation would track rapid connection attempts
	// to multiple ports from the same IP
}
