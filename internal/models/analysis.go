package models

type PacketStats struct {
    LengthStats  map[int]int     // packet length distribution
    EtherStats   map[string]int  // ethernet statistics
    TCPStats     map[string]int  // tcp statistics
    UDPStats     map[string]int  // udp statistics
}

// Example function to create a new PacketStats
func NewPacketStats() *PacketStats {
    return &PacketStats{
        LengthStats: make(map[int]int),
        EtherStats:  make(map[string]int),
        TCPStats:    make(map[string]int),
        UDPStats:    make(map[string]int),
    }
}
