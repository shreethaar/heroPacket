package analysis

import (
	"heroPacket/internal/models"
	"sync"
)

type HTTPAnalyzer struct {
	mu          sync.Mutex
	Methods     map[string]int // HTTP method -> count
	StatusCodes map[int]int    // Status code -> count
	Hosts       map[string]int // Host -> count
	UserAgents  map[string]int // User-Agent -> count
}

func NewHTTPAnalyzer() *HTTPAnalyzer {
	return &HTTPAnalyzer{
		Methods:     make(map[string]int),
		StatusCodes: make(map[int]int),
		Hosts:       make(map[string]int),
		UserAgents:  make(map[string]int),
	}
}

func (h *HTTPAnalyzer) Process(packet models.Packet) {
	// Add HTTP packet processing logic
	// This would require extending the models.Packet struct
	// to include HTTP-specific fields
}
