package handler

import (
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"heroPacket/internal/analysis"
	"heroPacket/internal/middleware"
	"heroPacket/internal/models"
	"heroPacket/view/analytics"
	"heroPacket/view/docs"
	"heroPacket/view/home"
	"heroPacket/view/overview"
	"heroPacket/view/upload"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type UserHandler struct {
	analysisCache map[string]*analysis.Session
	cacheMutex    sync.RWMutex
}

func NewUserHandler() *UserHandler {
	return &UserHandler{
		analysisCache: make(map[string]*analysis.Session),
	}
}

func (h *UserHandler) HandleMainPage(c echo.Context) error {
	return render(c, home.Show())
}

func (h *UserHandler) HandleHomePage(c echo.Context) error {
	csrfToken := c.Get("csrf").(string)

	// Read files from uploads directory
	files := []home.UploadedFile{}
	entries, err := os.ReadDir("uploads")
	if err == nil { // Don't fail if directory doesn't exist
		for _, entry := range entries {
			if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".pcap") || strings.HasSuffix(entry.Name(), ".pcapng")) {
				info, err := entry.Info()
				if err != nil {
					continue
				}
				files = append(files, home.UploadedFile{
					Name:       entry.Name(),
					Size:       info.Size(),
					UploadTime: info.ModTime(),
				})
			}
		}
	}

	// Sort files by upload time, newest first
	sort.Slice(files, func(i, j int) bool {
		return files[i].UploadTime.After(files[j].UploadTime)
	})

	return render(c, home.ShowHome(csrfToken, files))
}

func (h *UserHandler) HandleUpload(c echo.Context) error {
	if c.Request().Method != http.MethodPost {
		return c.String(http.StatusMethodNotAllowed, "Method not allowed")
	}

	csrfToken := c.Get("csrf").(string)

	// Helper function to get files list
	getFiles := func() []home.UploadedFile {
		files := []home.UploadedFile{}
		entries, err := os.ReadDir("uploads")
		if err == nil { // Don't fail if directory doesn't exist
			for _, entry := range entries {
				if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".pcap") || strings.HasSuffix(entry.Name(), ".pcapng")) {
					info, err := entry.Info()
					if err != nil {
						continue
					}
					files = append(files, home.UploadedFile{
						Name:       entry.Name(),
						Size:       info.Size(),
						UploadTime: info.ModTime(),
					})
				}
			}
		}
		sort.Slice(files, func(i, j int) bool {
			return files[i].UploadTime.After(files[j].UploadTime)
		})
		return files
	}

	// Retrieve validated file
	pcapFile, ok := c.Get("pcapFile").(middleware.PCAPFile)
	if !ok {
		return render(c, home.ShowHome(csrfToken, getFiles())) // Return to home page with error
	}

	// Process PCAP using analysis package
	packets, err := analysis.ExtractPackets(pcapFile.Path)
	if err != nil {
		return render(c, home.ShowHome(csrfToken, getFiles())) // Return to home page with error
	}

	// Create analysis session
	sessionID := uuid.New().String()
	session := analysis.NewSession()

	// Process packets concurrently
	var wg sync.WaitGroup
	for _, packet := range packets {
		wg.Add(1)
		go func(p models.Packet) { // Changed pcap.Packet to models.Packet
			defer wg.Done()
			session.Process(p)
		}(packet)
	}
	wg.Wait()

	// Store session in cache
	h.cacheMutex.Lock()
	h.analysisCache[sessionID] = session
	h.cacheMutex.Unlock()

	// Set cache expiration
	go h.clearCacheAfter(sessionID, 30*time.Minute)

	// Prepare view data
	viewData := upload.ViewData{
		SessionID:     sessionID,
		PacketCount:   len(packets),
		TopProtocols:  session.Protocols().Top(3),
		TrafficStats:  session.TrafficStats(),
		Conversations: session.Conversations().Top(5),
		CSRFToken:     csrfToken, // Add CSRF token
	}

	return render(c, upload.Show(viewData)) // Show analysis results
}

// HTMX Handlers for visualizations
func (h *UserHandler) ProtocolChart(c echo.Context) error {
	sessionID := c.Param("sessionID")

	h.cacheMutex.RLock()
	session, exists := h.analysisCache[sessionID]
	h.cacheMutex.RUnlock()

	if !exists {
		return c.String(http.StatusNotFound, "Session expired")
	}

	c.Response().Header().Set(echo.HeaderContentType, "image/svg+xml")
	return session.ProtocolChart().Render(c.Response().Writer)
}

func (h *UserHandler) TrafficTimeline(c echo.Context) error {
	sessionID := c.Param("sessionID")

	h.cacheMutex.RLock()
	session, exists := h.analysisCache[sessionID]
	h.cacheMutex.RUnlock()

	if !exists {
		return c.String(http.StatusNotFound, "Session expired")
	}

	c.Response().Header().Set(echo.HeaderContentType, "image/svg+xml")
	return session.TrafficTimeline().Render(c.Response().Writer)
}

func (h *UserHandler) HandleOverview(c echo.Context) error {
	filename := c.Param("filename")
	if filename == "" {
		return render(c, overview.Show(overview.ViewData{
			TrafficStats:  &analysis.TrafficStats{},
			TopProtocols:  []analysis.ProtocolCount{},
			Conversations: []*analysis.Conversation{},
			NetworkNodes:  []*analysis.NetworkNode{},
			DNSQueries:    []analysis.QueryCount{},
		}))
	}

	// Process file and create session if needed
	filePath := "uploads/" + filename
	packets, err := analysis.ExtractPackets(filePath)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error processing PCAP file")
	}

	session := analysis.NewSession()
	for _, packet := range packets {
		session.Process(packet)
	}

	viewData := overview.ViewData{
		Filename:      filename,
		TrafficStats:  session.TrafficStats(),
		TopProtocols:  session.Protocols().Top(10),
		Conversations: session.Conversations().Top(5),
		NetworkNodes:  session.NetworkMap().GetActiveNodes(),
		DNSQueries:    session.DNS().TopQueries(5),
	}

	return render(c, overview.Show(viewData))
}

func (h *UserHandler) HandleAnalytics(c echo.Context) error {
	filename := c.Param("filename")
	if filename == "" {
		return render(c, analytics.Show(analytics.ViewData{}))
	}

	// Process file and create session
	filePath := "uploads/" + filename
	packets, err := analysis.ExtractPackets(filePath)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error processing PCAP file")
	}

	session := analysis.NewSession()
	for _, packet := range packets {
		session.Process(packet)
	}

	viewData := analytics.ViewData{
		Filename:      filename,
		TrafficStats:  session.TrafficStats(),
		TopProtocols:  session.Protocols().Top(10),
		Conversations: session.Conversations().Top(10),
	}

	return render(c, analytics.Show(viewData))
}

func (h *UserHandler) HandleDocs(c echo.Context) error {
	return render(c, docs.Show())
}

func (h *UserHandler) HandleAnalyze(c echo.Context) error {
	filename := c.Param("filename")

	// Check if file exists
	filePath := "uploads/" + filename
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return c.String(http.StatusNotFound, "File not found")
	}

	// Redirect directly to overview page with filename
	return c.Redirect(http.StatusSeeOther, "/overview/"+filename)
}

func (h *UserHandler) clearCacheAfter(sessionID string, duration time.Duration) {
	time.Sleep(duration)
	h.cacheMutex.Lock()
	delete(h.analysisCache, sessionID)
	h.cacheMutex.Unlock()
}
