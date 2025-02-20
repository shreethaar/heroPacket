package models

import (
    "time"
    "heroPacket/internal/pcap"
)


type AnalysisJob struct {
    ID           string
    Filename     string
    Status       string // "pending", "processing", "completed", "error"
    ErrorMessage string
    StartTime    time.Time
    EndTime      time.Time
    PacketStats  *pcap.PacketStats
    TotalPackets int64
}
