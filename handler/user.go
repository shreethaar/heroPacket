package handler

import (
	"crypto/md5"
	"fmt"
	"heroPacket/internal/analysis"
	"heroPacket/view/analytics"
	"heroPacket/view/docs"
	"heroPacket/view/home"
	"heroPacket/view/overview"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

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

	// CSRF token is handled automatically by the Echo framework
	return render(c, home.ShowHome(files, nil))
}

func (h *UserHandler) HandleUpload(c echo.Context) error {
	if c.Request().Method == http.MethodPost {
		// Get the file from the request
		file, err := c.FormFile("pcap-file")
		if err != nil {
			log.Printf("Error getting file from request: %v", err)
			return render(c, home.UploadResponseTemplate(home.UploadResponse{
				Status:  "error",
				Message: "Failed to get file from request",
			}))
		}

		// Check if file is empty
		if file.Size == 0 {
			return render(c, home.UploadResponseTemplate(home.UploadResponse{
				Status:  "error",
				Message: "File is empty",
			}))
		}

		// Check file extension
		filename := file.Filename
		if !strings.HasSuffix(strings.ToLower(filename), ".pcap") && !strings.HasSuffix(strings.ToLower(filename), ".pcapng") {
			return render(c, home.UploadResponseTemplate(home.UploadResponse{
				Status:  "error",
				Message: "Invalid file type. Only .pcap and .pcapng files are allowed",
			}))
		}

		// Open the file
		src, err := file.Open()
		if err != nil {
			log.Printf("Error opening file: %v", err)
			return render(c, home.UploadResponseTemplate(home.UploadResponse{
				Status:  "error",
				Message: "Failed to open file",
			}))
		}
		defer src.Close()

		// Read the file content for hash calculation
		fileContent, err := io.ReadAll(src)
		if err != nil {
			log.Printf("Error reading file content: %v", err)
			return render(c, home.UploadResponseTemplate(home.UploadResponse{
				Status:  "error",
				Message: "Failed to read file content",
			}))
		}

		// Calculate MD5 hash of the file
		hash := md5.Sum(fileContent)
		hashStr := fmt.Sprintf("%x", hash)

		// Check if we already have this file (by hash)
		h.hashMutex.RLock()
		existingFilename, exists := h.fileHashes[hashStr]
		h.hashMutex.RUnlock()

		if exists {
			log.Printf("File with hash %s already exists as %s", hashStr, existingFilename)
			return render(c, home.UploadResponseTemplate(home.UploadResponse{
				Status:  "error",
				Message: fmt.Sprintf("This file already exists as %s", existingFilename),
			}))
		}

		// Create uploads directory if it doesn't exist
		if err := os.MkdirAll("uploads", 0755); err != nil {
			log.Printf("Error creating uploads directory: %v", err)
			return render(c, home.UploadResponseTemplate(home.UploadResponse{
				Status:  "error",
				Message: "Failed to create uploads directory",
			}))
		}

		// Generate a unique filename to prevent overwriting
		// Use the original filename but add a timestamp if needed
		baseFilename := filepath.Base(filename)
		uniqueFilename := baseFilename
		filePath := filepath.Join("uploads", uniqueFilename)

		// Check if file already exists and generate a unique name if needed
		for i := 1; fileExists(filePath); i++ {
			ext := filepath.Ext(baseFilename)
			name := strings.TrimSuffix(baseFilename, ext)
			uniqueFilename = fmt.Sprintf("%s_%d%s", name, i, ext)
			filePath = filepath.Join("uploads", uniqueFilename)
		}

		// Create the destination file
		dst, err := os.Create(filePath)
		if err != nil {
			log.Printf("Error creating destination file: %v", err)
			return render(c, home.UploadResponseTemplate(home.UploadResponse{
				Status:  "error",
				Message: "Failed to create destination file",
			}))
		}
		defer dst.Close()

		// Write the content to the destination file
		if _, err = dst.Write(fileContent); err != nil {
			log.Printf("Error writing to destination file: %v", err)
			return render(c, home.UploadResponseTemplate(home.UploadResponse{
				Status:  "error",
				Message: "Failed to write to destination file",
			}))
		}

		// Save the hash to filename mapping
		h.saveFileHash(hashStr, uniqueFilename)

		log.Printf("File uploaded successfully: %s", uniqueFilename)
		
		// Get the updated file list
		files := h.getUploadedFiles()
		
		// Set HX-Refresh header to force a refresh of the file list
		c.Response().Header().Set("HX-Refresh", "true")
		
		// Return the updated file list
		return render(c, home.FileListTemplate(files))
	}

	// If it's not a POST request, just render the upload form
	return c.HTML(http.StatusOK, "Upload form should be accessed via the home page")
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
		return render(c, analytics.Show(analytics.ViewData{}))
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

// getUploadedFiles returns the list of uploaded files
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

// HandleRefreshFiles handles the AJAX request to refresh the file list
func (h *UserHandler) HandleRefreshFiles(c echo.Context) error {
	// Read files from uploads directory
	files := h.getUploadedFiles()

	return render(c, home.FileListTemplate(files))
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}
