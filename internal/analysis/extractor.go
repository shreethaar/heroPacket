package analysis

import (
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "heroPacket/internal/models"
)

type PacketMetadata struct {
    Timestamp    time.Time
    CaptureInfo  gopacket.CaptureInfo
    HasErrors    bool
    ErrorMessage string
}

type PacketDetails struct {

    LinkLayer struct {
        Source      string
        Destination string
        EtherType   string
    }
    NetworkLayer struct {
        Version     uint8
        Source      string
        Destination string
        Protocol    string
        TTL         uint8
        Length      uint16
    }
    TransportLayer struct {
        Protocol    string
        SourcePort  uint16
        DestPort    uint16
        Length      uint16
        Payload     []byte
    }
    ApplicationLayer struct {
        Protocol    string
        PayloadSize int
        Payload     []byte
    }
}


type PacketProcessor interface {
    Process(models.Packet)
}


func ExtractPackets(filePath string) ([]models.Packet, error) {
    handle, err := pcap.OpenOffline(filePath)
    if err != nil {
        return nil, err
    }
    defer handle.Close()

    source := gopacket.NewPacketSource(handle, handle.LinkType())
    var packets []models.Packet

    for packet := range source.Packets() {
        packets = append(packets, extractPacketInfo(packet))
    }

    return packets, nil
}

func extractPacketInfo(packet gopacket.Packet) models.Packet {
    metadata := extractMetadata(packet)
    details := extractDetails(packet)
    dnsInfo := extractDNSInfo(packet)

    return models.Packet{
        Timestamp:   metadata.Timestamp,
        SourceIP:    details.NetworkLayer.Source,
        DestIP:      details.NetworkLayer.Destination,
        Protocol:    details.TransportLayer.Protocol,
        Length:      int(details.NetworkLayer.Length),
        SourcePort:  details.TransportLayer.SourcePort,
        DestPort:    details.TransportLayer.DestPort,
        DNS:         dnsInfo,
    }
}

func extractMetadata(packet gopacket.Packet) *PacketMetadata {
    metadata := &PacketMetadata{
        Timestamp:   packet.Metadata().Timestamp,
        CaptureInfo: packet.Metadata().CaptureInfo,
        HasErrors:   packet.ErrorLayer() != nil,
    }
    
    if metadata.HasErrors {
        metadata.ErrorMessage = packet.ErrorLayer().Error().Error()
    }
    
    return metadata
}


func extractDetails(packet gopacket.Packet) *PacketDetails {
    details := &PacketDetails{}
    if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
        eth, _ := ethLayer.(*layers.Ethernet)
        details.LinkLayer.Source = eth.SrcMAC.String()
        details.LinkLayer.Destination = eth.DstMAC.String()
        details.LinkLayer.EtherType = eth.EthernetType.String()
    }
    if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
        ipv4, _ := ipv4Layer.(*layers.IPv4)
        details.NetworkLayer.Version = 4
        details.NetworkLayer.Source = ipv4.SrcIP.String()
        details.NetworkLayer.Destination = ipv4.DstIP.String()
        details.NetworkLayer.Protocol = ipv4.Protocol.String()
        details.NetworkLayer.TTL = ipv4.TTL
        details.NetworkLayer.Length = ipv4.Length
    } else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
        ipv6, _ := ipv6Layer.(*layers.IPv6)
        details.NetworkLayer.Version = 6
        details.NetworkLayer.Source = ipv6.SrcIP.String()
        details.NetworkLayer.Destination = ipv6.DstIP.String()
        details.NetworkLayer.Protocol = ipv6.NextHeader.String()
        details.NetworkLayer.Length = uint16(ipv6.Length)
    }
    if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
        tcp, _ := tcpLayer.(*layers.TCP)
        details.TransportLayer.Protocol = "TCP"
        details.TransportLayer.SourcePort = uint16(tcp.SrcPort)
        details.TransportLayer.DestPort = uint16(tcp.DstPort)
        details.TransportLayer.Payload = tcp.Payload
    } else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)
        details.TransportLayer.Protocol = "UDP"
        details.TransportLayer.SourcePort = uint16(udp.SrcPort)
        details.TransportLayer.DestPort = uint16(udp.DstPort)
        details.TransportLayer.Length = uint16(udp.Length)
        details.TransportLayer.Payload = udp.Payload
    }
    if appLayer := packet.ApplicationLayer(); appLayer != nil {
        details.ApplicationLayer.Protocol = appLayer.LayerType().String()
        details.ApplicationLayer.PayloadSize = len(appLayer.Payload())
        details.ApplicationLayer.Payload = appLayer.Payload()
    }
    
    return details
}
func extractDNSInfo(packet gopacket.Packet) *DNSInfo {
    dnsLayer := packet.Layer(layers.LayerTypeDNS)
    if dnsLayer == nil {
        return nil
    }

    dns, _ := dnsLayer.(*layers.DNS)
    return &DNSInfo{
        QR:           dns.QR,
        OpCode:       dns.OpCode.String(),
        Questions:    extractDNSQuestions(dns),
        Answers:      extractDNSAnswers(dns),
        ResponseCode: dns.ResponseCode.String(),
    }
}
type DNSInfo struct {
    QR           bool      
    OpCode       string    
    Questions    []string  
    Answers      []string  
    ResponseCode string    
}

func extractDNSQuestions(dns *layers.DNS) []string {
    var questions []string
    for _, q := range dns.Questions {
        questions = append(questions, string(q.Name))
    }
    return questions
}

func extractDNSAnswers(dns *layers.DNS) []string {
    var answers []string
    for _, a := range dns.Answers {
        answers = append(answers, string(a.Name))
    }
    return answers
}
