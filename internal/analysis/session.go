package analysis

import (
    "heroPacket/internal/models"
    "sort"
)

type Session struct {
    protocols    *ProtocolAnalyzer
    stats        *TrafficStats
    conversations *ConversationTracker
}

func NewSession() *Session {
    return &Session{
        protocols:    NewProtocolAnalyzer(),
        stats:        NewTrafficStats(),
        conversations: NewConversationTracker(),
    }
}

func (s *Session) Process(p models.Packet) {
    s.protocols.Process(p)
    s.stats.Process(p)
    s.conversations.Process(p)
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
