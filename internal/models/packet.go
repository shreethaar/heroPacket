package models

import "time"

type Packet struct {
    Timestamp  time.Time
    SourceIP   string
    DestIP     string
    Protocol   string
    Length     int
    SourcePort uint16
    DestPort   uint16
    DNS        *DNSInfo
}

type DNSInfo struct {
    QR           bool
    OpCode       string
    Questions    []string
    Answers      []string
    ResponseCode string
}
