package analysis

import (
	"heroPacket/internal/models"
	"sort"
	"sync"
)

type DNSAnalyzer struct {
	mu      sync.Mutex
	Queries map[string]int // Domain -> count
	Types   map[string]int // Query type -> count
	Answers map[string]int // Answer -> count
}

func NewDNSAnalyzer() *DNSAnalyzer {
	return &DNSAnalyzer{
		Queries: make(map[string]int),
		Types:   make(map[string]int),
		Answers: make(map[string]int),
	}
}

func (d *DNSAnalyzer) Process(packet models.Packet) {
	if packet.DNS == nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Process DNS queries
	for _, q := range packet.DNS.Questions {
		d.Queries[q]++
	}

	// Process DNS answers
	for _, a := range packet.DNS.Answers {
		d.Answers[a]++
	}

	// Process operation type
	d.Types[packet.DNS.OpCode]++
}

func (d *DNSAnalyzer) TopQueries(n int) []QueryCount {
	d.mu.Lock()
	defer d.mu.Unlock()

	var counts []QueryCount
	for domain, count := range d.Queries {
		counts = append(counts, QueryCount{Domain: domain, Count: count})
	}

	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})

	if len(counts) > n {
		return counts[:n]
	}
	return counts
}

type QueryCount struct {
	Domain string
	Count  int
}
