//Read and parse pcap

package pcap

import (
    "fmt"
    "net"
    "sync"
    "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)


type PacketStats struct {
    TotalBytes int              // total bytes
    PPSStats map[int]int        // packet per second
    LengthStats map[int]int     // packet length distribution
    EtherStats  map[string]int  // ethernet statistics
    TCPStats map[string]int     // tcp statistics
    UDPStats map[string]int     // udp statistics
}

type Connection struct {
    SrcIP net.IP 
    DstIP net.IP 
    SrcPort uint16
    DstPort uint16
    Protocol uint8
    State string
    Bytes int
    Packets int
}

type TCPState struct {
    SYN,ACK,PSH,FIN,RST bool
}

var (
    packetStats PacketStats
    connectionMap sync.Map 
)

func init() {
    packetStats = PacketStats {
        PPSStats:make(map[int]int),
        LengthStats:make(map[int]int),
        EtherStats:make(map[string]int),
        TCPStats:make(map[string]int),
        UDPStats:make(map[string]int),
    }

}

func ProcessPacket(packet gopacket.Packet) {
    updatePacketLengthStats(packet) 
    processEthernetLayer(packet)
    srcIP,dstIP,ipProto:=processIPLayer(packet) 
    srcPort,dstPort,tcpState:=processTransportLayer(packet,ipProto)
    if srcIP!=nil && dstIP != nil {
        updateConnectionStats(srcIP,dstIP,srcPort,dstPort,ipProto,tcpState,packet.Metadata().Length) 
    }
}

func updatePacketLengthStats(packet gopacket.Packet) {
	packetLength := packet.Metadata().Length
	packetStats.TotalBytes += packetLength
	packetTime := int(packet.Metadata().Timestamp.Unix())
	packetStats.PPSStats[packetTime]++
	switch {
	case packetLength <= 66:
		packetStats.LengthStats[66]++
	case packetLength <= 128:
		packetStats.LengthStats[128]++
	case packetLength <= 256:
		packetStats.LengthStats[256]++
	case packetLength <= 384:
		packetStats.LengthStats[384]++
	case packetLength <= 512:
		packetStats.LengthStats[512]++
	case packetLength <= 768:
		packetStats.LengthStats[768]++
	case packetLength <= 1024:
		packetStats.LengthStats[1024]++
	case packetLength <= 1518:
		packetStats.LengthStats[1518]++
	default:
		packetStats.LengthStats[9000]++
	}
}

func processEthernetLayer(packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		etherType := ethernetPacket.EthernetType.String()
		packetStats.EtherStats[etherType]++
	} else {
		packetStats.EtherStats["unknown"]++
	}
}

func processIPLayer(packet gopacket.Packet) (srcIP, dstIP net.IP, ipProto uint8) {
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4Packet, _ := ipv4Layer.(*layers.IPv4)
		srcIP, dstIP, ipProto = ipv4Packet.SrcIP, ipv4Packet.DstIP, uint8(ipv4Packet.Protocol)
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6Packet, _ := ipv6Layer.(*layers.IPv6)
		srcIP, dstIP, ipProto = ipv6Packet.SrcIP, ipv6Packet.DstIP, uint8(ipv6Packet.NextHeader)
	}
	return
}

func processTransportLayer(packet gopacket.Packet, ipProto uint8) (srcPort, dstPort uint16, tcpState TCPState) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcpPacket, _ := tcpLayer.(*layers.TCP)
		srcPort, dstPort = uint16(tcpPacket.SrcPort), uint16(tcpPacket.DstPort)
		tcpState = TCPState{SYN: tcpPacket.SYN, ACK: tcpPacket.ACK, PSH: tcpPacket.PSH, FIN: tcpPacket.FIN, RST: tcpPacket.RST}
		packetStats.TCPStats["count"]++
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udpPacket, _ := udpLayer.(*layers.UDP)
		srcPort, dstPort = uint16(udpPacket.SrcPort), uint16(udpPacket.DstPort)
		packetStats.UDPStats["count"]++
	}
	return
}

func updateConnectionStats(srcIP, dstIP net.IP, srcPort, dstPort uint16, ipProto uint8, tcpState TCPState, packetLength int) {
	hash := connectionHash(srcIP, dstIP, srcPort, dstPort, ipProto)
	conn, exists := connectionMap.Load(hash)
	if !exists {
		conn = &Connection{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: ipProto,
			State:    "new",
			Bytes:    packetLength,
			Packets:  1,
		}
		connectionMap.Store(hash, conn)
	} else {
		existingConn := conn.(*Connection)
		existingConn.Bytes += packetLength
		existingConn.Packets++
		existingConn.State = determineConnectionState(tcpState, existingConn.State)
	}
}

func connectionHash(srcIP, dstIP net.IP, srcPort, dstPort uint16, ipProto uint8) string {
	return fmt.Sprintf("%s:%d->%s:%d:%d", srcIP, srcPort, dstIP, dstPort, ipProto)
}

func determineConnectionState(tcpState TCPState, currentState string) string {
	if tcpState.SYN && !tcpState.ACK {
		return "syn_sent"
	} else if tcpState.SYN && tcpState.ACK {
		return "established"
	} else if tcpState.FIN {
		return "closed"
	}
	return currentState
}
