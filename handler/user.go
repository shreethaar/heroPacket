package handler

import (
	"fmt"
	"heroPacket/internal/analysis"
	"heroPacket/view/docs"
	"heroPacket/view/home"
	"heroPacket/view/overview"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
    "heroPacket/internal/middleware"
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
	files := h.getUploadedFiles()
	return render(c, home.ShowHome(files, nil))
}

// HandleUpload handles file upload requests

func (h *UserHandler) HandleUpload(c echo.Context) error {
	// Retrieve validated PCAP file from middleware
	pcapFile, ok := c.Get("pcapFile").(middleware.PCAPFile)
	if !ok {
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: "Failed to retrieve uploaded file",
		}))
	}

	// Save file hash to prevent duplicates
	hashStr := pcapFile.Hash
	h.hashMutex.RLock()
	if existingFile, exists := h.fileHashes[hashStr]; exists {
		h.hashMutex.RUnlock()
		os.Remove(pcapFile.Path) // Remove duplicate file
		return render(c, home.UploadResponseTemplate(home.UploadResponse{
			Status:  "error",
			Message: fmt.Sprintf("This file has already been uploaded as %s", existingFile),
		}))
	}
	h.hashMutex.RUnlock()

	h.saveFileHash(hashStr, pcapFile.Path)

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

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}
