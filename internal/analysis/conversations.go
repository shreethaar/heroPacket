package analysis

import (
    "heroPacket/internal/models"
    "sync"
)

type ConversationTracker struct {
    mu            sync.Mutex
    Conversations map[string]*Conversation
}

type Conversation struct {
    SourceIP    string
    DestIP      string
    Protocol    string
    PacketCount int
    TotalBytes  int
}

func NewConversationTracker() *ConversationTracker {
    return &ConversationTracker{
        Conversations: make(map[string]*Conversation),
    }
}

func (c *ConversationTracker) Process(packet models.Packet) {
    key := conversationKey(packet)
    
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if conv, exists := c.Conversations[key]; exists {
        conv.PacketCount++
        conv.TotalBytes += packet.Length
    } else {
        c.Conversations[key] = &Conversation{
            SourceIP:    packet.SourceIP,
            DestIP:      packet.DestIP,
            Protocol:    packet.Protocol,
            PacketCount: 1,
            TotalBytes:  packet.Length,
        }
    }
}

func conversationKey(packet models.Packet) string {
    return packet.SourceIP + ":" + packet.DestIP + ":" + packet.Protocol
}
