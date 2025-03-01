package analysis

import (
	"heroPacket/internal/models"
	"io"
	"sort"
)

type Session struct {
	protocols     *ProtocolAnalyzer
	stats         *TrafficStats
	conversations *ConversationTracker
	dns           *DNSAnalyzer
	http          *HTTPAnalyzer
	security      *SecurityAnalyzer
	networkMap    *NetworkMapAnalyzer
}

func NewSession() *Session {
	return &Session{
		protocols:     NewProtocolAnalyzer(),
		stats:         NewTrafficStats(),
		conversations: NewConversationTracker(),
		dns:           NewDNSAnalyzer(),
		http:          NewHTTPAnalyzer(),
		security:      NewSecurityAnalyzer(),
		networkMap:    NewNetworkMapAnalyzer(),
	}
}

func (s *Session) Process(p models.Packet) {
	s.protocols.Process(p)
	s.stats.Process(p)
	s.conversations.Process(p)
	s.dns.Process(p)
	s.http.Process(p)
	s.security.Process(p)
	s.networkMap.Process(p)
}

func (s *Session) Protocols() *ProtocolAnalyzer {
	return s.protocols
}

func (s *Session) TrafficStats() *TrafficStats {
	return s.stats
}

func (s *Session) Conversations() *ConversationTracker {
	return s.conversations
}

// Add these to existing analyzer structs if missing
type ProtocolCount struct {
	Name  string
	Count int
}

func (p *ProtocolAnalyzer) Top(n int) []ProtocolCount {
	p.mu.Lock()
	defer p.mu.Unlock()

	var counts []ProtocolCount
	for name, count := range p.Protocols {
		counts = append(counts, ProtocolCount{Name: name, Count: count})
	}

	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})

	if len(counts) > n {
		return counts[:n]
	}
	return counts
}

func (c *ConversationTracker) Top(n int) []*Conversation {
	c.mu.Lock()
	defer c.mu.Unlock()

	conversations := make([]*Conversation, 0, len(c.Conversations))
	for _, conv := range c.Conversations {
		conversations = append(conversations, conv)
	}

	sort.Slice(conversations, func(i, j int) bool {
		return conversations[i].PacketCount > conversations[j].PacketCount
	})

	if len(conversations) > n {
		return conversations[:n]
	}
	return conversations
}

// Add these methods to your Session type
func (s *Session) ProtocolChart() *Chart {
	// Implement chart generation logic here
	// Return a Chart type that has a Render method
	return &Chart{
		// Initialize with protocol data
		data: s.Protocols(),
	}
}

func (s *Session) TrafficTimeline() *Chart {
	// Implement timeline generation logic here
	// Return a Chart type that has a Render method
	return &Chart{
		// Initialize with traffic data
		data: s.TrafficStats(),
	}
}

// You'll need a Chart type with a Render method
type Chart struct {
	data interface{}
}

func (c *Chart) Render(w io.Writer) error {
	// Implement SVG rendering logic here
	// This should convert the chart data into SVG format
	return nil
}

// Add getter for network map
func (s *Session) NetworkMap() *NetworkMapAnalyzer {
	return s.networkMap
}

func (s *Session) DNS() *DNSAnalyzer {
	return s.dns
}
