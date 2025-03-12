package handler

import (
	"fmt"
	"heroPacket/internal/analysis"
	"heroPacket/view/docs"
	"heroPacket/view/home"
	"heroPacket/view/overview"
    "heroPacket/view/properties"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"bytes"
    "io"
    "crypto/md5"
    "github.com/labstack/echo/v4"
    "encoding/json"
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
	files := h.getUploadedFiles()
	return render(c, home.ShowHome(files, nil))
}

// HandleUpload handles file upload requests
func (h *UserHandler) HandleUpload(c echo.Context) error {
	// Get file
	file, err := c.FormFile("file")
	if err != nil {
		log.Println("DEBUG: No file uploaded:", err)
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: "No file uploaded",
		}))
	}

	// Validate file size
	if file.Size > 100*1024*1024 {
		log.Println("DEBUG: File too large:", file.Size)
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: "File size exceeds 100MB limit",
		}))
	}

	// Open file
	src, err := file.Open()
	if err != nil {
		log.Println("DEBUG: Failed to open file:", err)
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: "Failed to read file",
		}))
	}
	defer src.Close()

	// Read first 14 bytes
	header := make([]byte, 14)
	_, err = src.Read(header)
	if err != nil {
		log.Println("DEBUG: Failed to read file header:", err)
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: "Failed to read file header",
		}))
	}

	// Validate PCAP-NG format
	if !bytes.Equal(header[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}) || 
	   !bytes.Equal(header[8:12], []byte{0x4d, 0x3c, 0x2b, 0x1a}) {
		log.Println("DEBUG: Invalid PCAP-NG magic number")
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: "Invalid file format. Expected a PCAP file.",
		}))
	}

	// Reset file pointer before saving
	_, err = src.Seek(0, io.SeekStart)
	if err != nil {
		log.Println("DEBUG: Failed to reset file pointer:", err)
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: "Failed to reset file pointer",
		}))
	}

	// Create uploads directory
	if err := os.MkdirAll("uploads", 0755); err != nil {
		log.Println("DEBUG: Failed to create uploads directory:", err)
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: "Failed to create uploads directory",
		}))
	}

	// Compute MD5 hash and save the file
	dstPath := filepath.Join("uploads", file.Filename)
	dst, err := os.Create(dstPath)
	if err != nil {
		log.Println("DEBUG: Failed to create destination file:", err)
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: "Failed to create destination file",
		}))
	}
	defer dst.Close()

	hash := md5.New()
	if _, err = io.Copy(io.MultiWriter(dst, hash), src); err != nil {
		os.Remove(dstPath) // Cleanup on error
		log.Println("DEBUG: Failed to save file:", err)
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: "Failed to save file",
		}))
	}

	// Convert hash to string
	hashStr := fmt.Sprintf("%x", hash.Sum(nil))

	// Check for duplicate file
	h.hashMutex.RLock()
	if existingFile, exists := h.fileHashes[hashStr]; exists {
		h.hashMutex.RUnlock()
		os.Remove(dstPath) // Remove duplicate file
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: fmt.Sprintf("This file has already been uploaded as %s", filepath.Base(existingFile)),
		}))
	}
	h.hashMutex.RUnlock()

	// Save file hash
	h.saveFileHash(hashStr, dstPath)

	// Trigger file list update
	c.Response().Header().Set("HX-Trigger", "fileListUpdate")
	return render(c, home.UploadResponseTemplate(home.UploadResponse{
		Status:  "success",
		Message: "File uploaded successfully",
	}))
}



// HandleRefreshFiles handles the AJAX request to refresh the file list
func (h *UserHandler) HandleRefreshFiles(c echo.Context) error {
	files := h.getUploadedFiles()
	return render(c, home.FileListTemplate(files))
}

// getUploadedFiles returns a list of uploaded files with details
func (h *UserHandler) getUploadedFiles() []home.UploadedFile {
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

	return files
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
		return render(c, home.ErrorTemplate("Error processing PCAP file"))
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
		return render(c, overview.Show(overview.ViewData{
			TrafficStats:  &analysis.TrafficStats{},
			TopProtocols:  []analysis.ProtocolCount{},
			Conversations: []*analysis.Conversation{},
			NetworkNodes:  []*analysis.NetworkNode{},
			DNSQueries:    []analysis.QueryCount{},
		}))
	}

	// Process file and create session
	filePath := "uploads/" + filename
	packets, err := analysis.ExtractPackets(filePath)
	if err != nil {
		return render(c, home.ErrorTemplate("Error processing PCAP file"))
	}

	session := analysis.NewSession()
	for _, packet := range packets {
		session.Process(packet)
	}

	viewData := overview.ViewData{
		Filename:      filename,
		TrafficStats:  session.TrafficStats(),
		TopProtocols:  session.Protocols().Top(10),
		Conversations: session.Conversations().Top(10),
	}

	return render(c, overview.Show(viewData))
}

func (h *UserHandler) HandleDocs(c echo.Context) error {
	return render(c, docs.Show())
}

func (h *UserHandler) HandleAnalyze(c echo.Context) error {
	filename := c.Param("filename")

	// Check if file exists
	filePath := "uploads/" + filename
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return render(c, home.ErrorTemplate("File not found"))
	}

	// Redirect directly to overview page with filename
	return c.Redirect(http.StatusSeeOther, "/overview/"+filename)
}

// HandleConfirmDelete shows the delete confirmation dialog
func (h *UserHandler) HandleConfirmDelete(c echo.Context) error {
	filename := c.Param("filename")
	if filename == "" {
		return render(c, home.ErrorTemplate("No filename provided"))
	}
	return render(c, home.DeleteConfirmationTemplate(filename))
}

// HandleDeleteFile handles the deletion of a PCAP file
func (h *UserHandler) HandleDeleteFile(c echo.Context) error {
	filename := c.Param("filename")
	if filename == "" {
		return render(c, home.ErrorTemplate("No filename provided"))
	}

	// Ensure the filename is safe and within the uploads directory
	filePath := filepath.Join("uploads", filepath.Base(filename))

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("File not found for deletion: %s", filePath)
		return render(c, home.ErrorTemplate("File not found"))
	}

	// Delete the file
	if err := os.Remove(filePath); err != nil {
		log.Printf("Error deleting file %s: %v", filePath, err)
		return render(c, home.ErrorTemplate("Failed to delete file"))
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

	// Return the updated file list template
	files := h.getUploadedFiles()
	return render(c, home.FileListTemplate(files))
}

// saveFileHash saves the hash to filename mapping
func (h *UserHandler) saveFileHash(hash string, filename string) {
	h.hashMutex.Lock()
	defer h.hashMutex.Unlock()
	h.fileHashes[hash] = filename
}

func (h *UserHandler) ProtocolChart(c echo.Context) error {
	sessionID := c.Param("sessionID")

	h.cacheMutex.RLock()
	session, exists := h.analysisCache[sessionID]
	h.cacheMutex.RUnlock()

	if !exists {
		return render(c, home.ErrorTemplate("Session expired"))
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
		return render(c, home.ErrorTemplate("Session expired"))
	}

	c.Response().Header().Set(echo.HeaderContentType, "image/svg+xml")
	return session.TrafficTimeline().Render(c.Response().Writer)
}

func (h *UserHandler) HandlePropertiesIndex(c echo.Context) error {
	// Get all files in the uploads directory
	files, err := os.ReadDir("uploads")
	if err != nil {
		return render(c, properties.Layout(nil, ""))
	}
	
	// Extract filenames
	var filenames []string
	for _, file := range files {
		if !file.IsDir() {
			filenames = append(filenames, file.Name())
		}
	}
	
	return render(c, properties.Layout(filenames, ""))
}

func (h *UserHandler) HandleProperties(c echo.Context) error {
	filename := c.Param("filename")
	
	// If no filename provided, return empty template
	if filename == "" {
		return c.String(http.StatusBadRequest, "Filename is required")
	}
	
	// Construct the file path
	filePath := "uploads/" + filename
	
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return render(c, properties.Show(properties.ViewData{
			Error: "File not found",
		}))
	}
	
	// Get capture properties
	propertiesJSON, err := analysis.GetCaptureProperties(filePath)
	if err != nil {
		return render(c, properties.Show(properties.ViewData{
			Error: "Failed to get capture properties: " + err.Error(),
		}))
	}
	
	// Parse JSON into CaptureProperties struct
	var captureProps analysis.CaptureProperties
	if err := json.Unmarshal([]byte(propertiesJSON), &captureProps); err != nil {
		return render(c, properties.Show(properties.ViewData{
			Error: "Failed to parse properties data",
		}))
	}
	
	// If this is an HTMX request, render only the Show component
	if c.Request().Header.Get("HX-Request") == "true" {
		return render(c, properties.Show(properties.ViewData{
			Filename:   filename,
			Properties: &captureProps,
		}))
	}
	
	// Otherwise, get all files and render the full layout
	files, err := os.ReadDir("uploads")
	if err != nil {
		files = []os.DirEntry{}
	}
	
	// Extract filenames
	var filenames []string
	for _, file := range files {
		if !file.IsDir() {
			filenames = append(filenames, file.Name())
		}
	}
	
	// Render the full layout with the selected file highlighted
	return render(c, properties.Layout(filenames, filename))
}
