package models

import (
    "time"
)

type AnalysisJob struct {
    ID            string
    Filename      string
    Status        string // "pending", "processing", "completed", "error"
    ErrorMessage  string
    StartTime     time.Time
    EndTime       time.Time
    TotalPackets  int64
}

type PacketStats struct {
    LengthStats  map[int]int     // packet length distribution
    EtherStats   map[string]int  // ethernet statistics
    TCPStats     map[string]int  // tcp statistics
    UDPStats     map[string]int  // udp statistics
}
