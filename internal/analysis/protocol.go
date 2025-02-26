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

func (a *ProtocolAnalyzer) Process(packet models.Packet) {
    a.mu.Lock()
    defer a.mu.Unlock()
    
    if packet.Protocol != "" {
        a.Protocols[packet.Protocol]++
    }
}

func (a *ProtocolAnalyzer) Results() map[string]int {
    a.mu.Lock()
    defer a.mu.Unlock()
    
    results := make(map[string]int)
    for k, v := range a.Protocols {
        results[k] = v
    }
    return results
}
