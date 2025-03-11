package handler

import (
	"bytes"
	"fmt"
	"heroPacket/internal/analysis"
	"heroPacket/internal/middleware"
	"heroPacket/view/analytics"
	"heroPacket/view/docs"
	"heroPacket/view/home"
	"heroPacket/view/overview"
	"heroPacket/view/upload"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

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

	// Get file from form
	file, err := c.FormFile("pcap-file")
	if err != nil {
		return render(c, upload.UploadError("No file uploaded"))
	}

	// Check file size
	if file.Size > middleware.MaxPCAPSize {
		return render(c, upload.UploadError("File size exceeds the allowed limit"))
	}

	// Open file
	src, err := file.Open()
	if err != nil {
		return render(c, upload.UploadError(fmt.Sprintf("Failed to open file: %v", err)))
	}
	defer src.Close()

	// Validate magic number
	header := make([]byte, 24)
	if _, err := io.ReadFull(src, header); err != nil {
		return render(c, upload.UploadError("Invalid file format"))
	}
	if !bytes.Equal(header[:4], []byte(middleware.PCAPMagicLE)) &&
		!bytes.Equal(header[:4], []byte(middleware.PCAPMagicBE)) &&
		!bytes.Equal(header[:4], []byte(middleware.PCAPMagicNS)) {
		return render(c, upload.UploadError("Invalid PCAP file signature"))
	}

	// Reset file reader
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return render(c, upload.UploadError(fmt.Sprintf("Failed to reset file reader: %v", err)))
	}

	// Ensure uploads directory exists
	if err := os.MkdirAll("uploads", 0755); err != nil {
		return render(c, upload.UploadError(fmt.Sprintf("Failed to create uploads directory: %v", err)))
	}

	// Generate a unique filename
	uniqueFilename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(file.Filename))
	dstPath := filepath.Join("uploads", uniqueFilename)

	// Save file
	dst, err := os.Create(dstPath)
	if err != nil {
		return render(c, upload.UploadError(fmt.Sprintf("Failed to save file: %v", err)))
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return render(c, upload.UploadError(fmt.Sprintf("Failed to copy file: %v", err)))
	}

	// Return success response
	return render(c, upload.UploadSuccess(file.Filename))
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
