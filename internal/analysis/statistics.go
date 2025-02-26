package analysis

import (
    "heroPacket/internal/models"
    "sync"
    "time"
)

type TrafficStats struct {
    mu             sync.Mutex
    TotalPackets   int
    TotalBytes     int
    StartTime      time.Time
    EndTime        time.Time
    SizeBuckets    map[string]int
}

func NewTrafficStats() *TrafficStats {
    return &TrafficStats{
        SizeBuckets: make(map[string]int),
    }
}

func (s *TrafficStats) Process(packet models.Packet) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    s.TotalPackets++
    s.TotalBytes += packet.Length
    
    // Update time range
    if s.StartTime.IsZero() || packet.Timestamp.Before(s.StartTime) {
        s.StartTime = packet.Timestamp
    }
    if packet.Timestamp.After(s.EndTime) {
        s.EndTime = packet.Timestamp
    }
    
    // Size bucket calculation
    bucket := getSizeBucket(packet.Length)
    s.SizeBuckets[bucket]++
}

func getSizeBucket(size int) string {
    switch {
    case size <= 64: return "≤64"
    case size <= 128: return "65-128"
    case size <= 512: return "129-512"
    case size <= 1024: return "513-1024"
    default: return ">1024"
    }
}
