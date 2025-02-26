package pcap

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

type PacketInfo struct {
    Timestamp string `json:"timestamp"`
    SourceIP  string `json:"source_ip"`  // Changed from SrcIP
    DestIP    string `json:"dest_ip"`    // Changed from DstIP
    Protocol  string `json:"protocol"`
    Length    int    `json:"length"`     // Added Length field
}

func ProcessPCAP(filePath string) ([]PacketInfo, error) {
    handle, err := pcap.OpenOffline(filePath)
    if err != nil {
        return nil, fmt.Errorf("error opening pcap file: %v", err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    var packets []PacketInfo

    for packet := range packetSource.Packets() {
        networkLayer := packet.NetworkLayer()
        transportLayer := packet.TransportLayer()
        
        if networkLayer != nil && transportLayer != nil {
            packets = append(packets, PacketInfo{
                Timestamp: packet.Metadata().Timestamp.String(),
                SourceIP:  networkLayer.NetworkFlow().Src().String(),
                DestIP:    networkLayer.NetworkFlow().Dst().String(),
                Protocol:  transportLayer.LayerType().String(),
                Length:    len(packet.Data()),
            })
        }
    }
    
    return packets, nil
}
