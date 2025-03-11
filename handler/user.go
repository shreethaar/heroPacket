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
	"log"
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
	fileHashes    map[string]string // Maps MD5 hash to filename
	cacheMutex    sync.RWMutex
	hashMutex     sync.RWMutex
}

func NewUserHandler() *UserHandler {
	return &UserHandler{
		analysisCache: make(map[string]*analysis.Session),
		fileHashes:    make(map[string]string),
	}
}

func (h *UserHandler) HandleMainPage(c echo.Context) error {
	return render(c, home.Show())
}

func (h *UserHandler) HandleHomePage(c echo.Context) error {
	// No CSRF token needed

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

	// No CSRF token needed
	return render(c, home.ShowHome(files))
}

func (h *UserHandler) HandleUpload(c echo.Context) error {
	if c.Request().Method != http.MethodPost {
		return c.String(http.StatusMethodNotAllowed, "Method not allowed")
	}

	// Check if we have a file from the form
	file, err := c.FormFile("pcap-file")
	if err != nil {
		log.Printf("No file uploaded: %v", err)
		return render(c, upload.UploadError("No file uploaded"))
	}

	log.Printf("Received file: %s, size: %d bytes", file.Filename, file.Size)

	// Check file size
	if file.Size > middleware.MaxPCAPSize {
		log.Printf("File size exceeds limit: %d bytes", file.Size)
		return render(c, upload.UploadError("File size exceeds the allowed limit"))
	}

	// Open file
	src, err := file.Open()
	if err != nil {
		log.Printf("Failed to open file: %v", err)
		return render(c, upload.UploadError(fmt.Sprintf("Failed to open file: %v", err)))
	}
	defer src.Close()

	// Validate magic number
	header := make([]byte, 24)
	n, err := io.ReadFull(src, header)
	if err != nil {
		log.Printf("Failed to read file header: %v, bytes read: %d", err, n)
		return render(c, upload.UploadError("Invalid file format"))
	}

	// Log the first 4 bytes for debugging
	log.Printf("File header (first 4 bytes): [%x %x %x %x]", header[0], header[1], header[2], header[3])

	// Check for standard PCAP formats
	isPcap := bytes.Equal(header[:4], []byte(middleware.PCAPMagicLE)) ||
		bytes.Equal(header[:4], []byte(middleware.PCAPMagicBE)) ||
		bytes.Equal(header[:4], []byte(middleware.PCAPMagicNS))

	// Check for PCAPNG format (0x0A0D0D0A)
	isPcapNg := bytes.Equal(header[:4], []byte{0x0A, 0x0D, 0x0D, 0x0A})

	if !isPcap && !isPcapNg {
		log.Printf("Invalid PCAP signature: %x", header[:4])
		return render(c, upload.UploadError("Invalid PCAP signature. Supported formats: PCAP, PCAPNG"))
	}

	// Reset file reader
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		log.Printf("Failed to reset file reader: %v", err)
		return render(c, upload.UploadError(fmt.Sprintf("Failed to reset file reader: %v", err)))
	}

	// Ensure uploads directory exists with proper permissions
	if err := os.MkdirAll("uploads", 0755); err != nil {
		log.Printf("Failed to create uploads directory: %v", err)
		return render(c, upload.UploadError(fmt.Sprintf("Failed to create uploads directory: %v", err)))
	}

	// Generate a unique filename
	uniqueFilename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(file.Filename))
	dstPath := filepath.Join("uploads", uniqueFilename)

	// Create destination file
	dst, err := os.Create(dstPath)
	if err != nil {
		log.Printf("Failed to create destination file: %v", err)
		return render(c, upload.UploadError(fmt.Sprintf("Failed to save file: %v", err)))
	}
	defer dst.Close()

	// Copy file contents
	bytesWritten, err := io.Copy(dst, src)
	if err != nil {
		log.Printf("Failed to copy file contents: %v", err)
		return render(c, upload.UploadError(fmt.Sprintf("Failed to save file: %v", err)))
	}

	// Log success
	log.Printf("Successfully uploaded file: %s to %s (%d bytes written)", file.Filename, dstPath, bytesWritten)

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

// HandleDeleteFile handles the deletion of a PCAP file
func (h *UserHandler) HandleDeleteFile(c echo.Context) error {
	filename := c.Param("filename")
	if filename == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "No filename provided"})
	}

	// Ensure the filename is safe and within the uploads directory
	filePath := filepath.Join("uploads", filename)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("File not found for deletion: %s", filePath)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "File not found"})
	}

	// Delete the file
	if err := os.Remove(filePath); err != nil {
		log.Printf("Error deleting file %s: %v", filePath, err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete file"})
	}

	// If we have a hash for this file, remove it from our hash map
	h.hashMutex.Lock()
	for hash, fname := range h.fileHashes {
		if fname == filename {
			delete(h.fileHashes, hash)
			break
		}
	}
	h.hashMutex.Unlock()

	log.Printf("Successfully deleted file: %s", filePath)
	return c.JSON(http.StatusOK, map[string]string{"message": "File deleted successfully"})
}

// saveFileHash saves the hash to filename mapping
func (h *UserHandler) saveFileHash(hash string, filename string) {
	h.hashMutex.Lock()
	defer h.hashMutex.Unlock()
	h.fileHashes[hash] = filename
}
