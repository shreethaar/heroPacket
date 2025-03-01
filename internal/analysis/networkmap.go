package analysis

import (
	"heroPacket/internal/models"
	"sync"
)

type NetworkNode struct {
	IP       string
	Type     string // "client", "server", "router", etc.
	Ports    map[uint16]bool
	Services map[string]bool
}

type NetworkConnection struct {
	Source      string
	Destination string
	Protocol    string
	Count       int
	LastSeen    int64 // Unix timestamp
}

type NetworkMapAnalyzer struct {
	mu           sync.Mutex
	Nodes        map[string]*NetworkNode
	Connections  map[string]*NetworkConnection
	ServicePorts map[uint16]string // Common service port mappings
}

func NewNetworkMapAnalyzer() *NetworkMapAnalyzer {
	return &NetworkMapAnalyzer{
		Nodes:       make(map[string]*NetworkNode),
		Connections: make(map[string]*NetworkConnection),
		ServicePorts: map[uint16]string{
			80:    "HTTP",
			443:   "HTTPS",
			22:    "SSH",
			23:    "Telnet",
			21:    "FTP",
			53:    "DNS",
			3389:  "RDP",
			445:   "SMB",
			139:   "NetBIOS",
			25:    "SMTP",
			110:   "POP3",
			143:   "IMAP",
			3306:  "MySQL",
			5432:  "PostgreSQL",
			27017: "MongoDB",
			6379:  "Redis",
		},
	}
}

func (n *NetworkMapAnalyzer) Process(packet models.Packet) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Process source node
	if _, exists := n.Nodes[packet.SourceIP]; !exists {
		n.Nodes[packet.SourceIP] = &NetworkNode{
			IP:       packet.SourceIP,
			Type:     n.determineNodeType(packet.SourceIP, packet.SourcePort),
			Ports:    make(map[uint16]bool),
			Services: make(map[string]bool),
		}
	}
	n.Nodes[packet.SourceIP].Ports[packet.SourcePort] = true
	if service, ok := n.ServicePorts[packet.SourcePort]; ok {
		n.Nodes[packet.SourceIP].Services[service] = true
	}

	// Process destination node
	if _, exists := n.Nodes[packet.DestIP]; !exists {
		n.Nodes[packet.DestIP] = &NetworkNode{
			IP:       packet.DestIP,
			Type:     n.determineNodeType(packet.DestIP, packet.DestPort),
			Ports:    make(map[uint16]bool),
			Services: make(map[string]bool),
		}
	}
	n.Nodes[packet.DestIP].Ports[packet.DestPort] = true
	if service, ok := n.ServicePorts[packet.DestPort]; ok {
		n.Nodes[packet.DestIP].Services[service] = true
	}

	// Process connection
	connKey := n.connectionKey(packet.SourceIP, packet.DestIP, packet.Protocol)
	if _, exists := n.Connections[connKey]; !exists {
		n.Connections[connKey] = &NetworkConnection{
			Source:      packet.SourceIP,
			Destination: packet.DestIP,
			Protocol:    packet.Protocol,
			Count:       0,
		}
	}
	n.Connections[connKey].Count++
	n.Connections[connKey].LastSeen = packet.Timestamp.Unix()
}

func (n *NetworkMapAnalyzer) determineNodeType(ip string, port uint16) string {
	// Simple heuristic: if the node is listening on well-known ports,
	// consider it a server
	if _, isService := n.ServicePorts[port]; isService {
		return "server"
	}
	return "client"
}

func (n *NetworkMapAnalyzer) connectionKey(src, dst, proto string) string {
	return src + "->" + dst + ":" + proto
}

// Get active nodes (nodes with recent activity)
func (n *NetworkMapAnalyzer) GetActiveNodes() []*NetworkNode {
	n.mu.Lock()
	defer n.mu.Unlock()

	var nodes []*NetworkNode
	for _, node := range n.Nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// Get active connections (connections with recent activity)
func (n *NetworkMapAnalyzer) GetActiveConnections() []*NetworkConnection {
	n.mu.Lock()
	defer n.mu.Unlock()

	var connections []*NetworkConnection
	for _, conn := range n.Connections {
		connections = append(connections, conn)
	}
	return connections
}

// Get services for a specific node
func (n *NetworkMapAnalyzer) GetNodeServices(ip string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()

	if node, exists := n.Nodes[ip]; exists {
		var services []string
		for service := range node.Services {
			services = append(services, service)
		}
		return services
	}
	return nil
}
