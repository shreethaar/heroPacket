package analysis

import (
    "heroPacket/internal/models"
    "sync"
)

type ProtocolAnalyzer struct {
    mu        sync.Mutex
    Protocols map[string]int
}

func NewProtocolAnalyzer() *ProtocolAnalyzer {
    return &ProtocolAnalyzer{
        Protocols: make(map[string]int),
    }
}

func (p *ProtocolAnalyzer) Process(packet models.Packet) {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    if packet.Protocol != "" {
        p.Protocols[packet.Protocol]++
    }
}
