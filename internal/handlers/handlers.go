package handlers

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/labstack/echo/v4"

	"heroPacket/internal/models"
	"heroPacket/internal/pcap"
	"heroPacket/view/home"
)

var (
	jobs      = make(map[string]*models.AnalysisJob)
	jobsMutex sync.RWMutex
)

// Home handles the root route
func Home(c echo.Context) error {
	files := []home.UploadedFile{} // Get your files list here
	return home.Show().Render(context.Background(), c.Response().Writer)
}

// ShowHome handles the dashboard route
func ShowHome(c echo.Context) error {
	files := []home.UploadedFile{} // Get your files list here
	return home.ShowHome(files, nil).Render(context.Background(), c.Response().Writer)
}

// UploadPCAP handles PCAP file uploads
func UploadPCAP(c echo.Context) error {
	// Get the file from the request
	file, err := c.FormFile("pcap-file")
	if err != nil {
		return home.ShowHome(nil, &home.UploadResponse{
			Status:  "error",
			Message: "Missing or invalid PCAP file",
		}).Render(context.Background(), c.Response().Writer)
	}

	// Check file extension
	if !strings.HasSuffix(strings.ToLower(file.Filename), ".pcap") {
		return home.ShowHome(nil, &home.UploadResponse{
			Status:  "error",
			Message: "Only .pcap files are allowed",
		}).Render(context.Background(), c.Response().Writer)
	}

	// Create uploads directory if it doesn't exist
	uploadsDir := "./uploads"
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		log.Printf("Failed to create uploads directory: %v", err)
		return home.ShowHome(nil, &home.UploadResponse{
			Status:  "error",
			Message: "Internal server error",
		}).Render(context.Background(), c.Response().Writer)
	}

	// Generate unique filename
	timestamp := time.Now().Unix()
	filename := fmt.Sprintf("%d_%s", timestamp, filepath.Clean(file.Filename))
	filePath := filepath.Join(uploadsDir, filename)

	// Check for duplicate file
	if _, err := os.Stat(filePath); err == nil {
		return home.ShowHome(nil, &home.UploadResponse{
			Status:  "error",
			Message: "File already exists",
		}).Render(context.Background(), c.Response().Writer)
	}

	// Open uploaded file
	src, err := file.Open()
	if err != nil {
		return home.ShowHome(nil, &home.UploadResponse{
			Status:  "error",
			Message: "Failed to process uploaded file",
		}).Render(context.Background(), c.Response().Writer)
	}
	defer src.Close()

	// Create destination file
	dst, err := os.Create(filePath)
	if err != nil {
		log.Printf("Failed to create destination file: %v", err)
		return home.ShowHome(nil, &home.UploadResponse{
			Status:  "error",
			Message: "Failed to save file",
		}).Render(context.Background(), c.Response().Writer)
	}
	defer dst.Close()

	// Copy uploaded file
	if _, err = io.Copy(dst, src); err != nil {
		log.Printf("Failed to save uploaded file: %v", err)
		os.Remove(filePath) // Clean up partial file
		return home.ShowHome(nil, &home.UploadResponse{
			Status:  "error",
			Message: "Failed to save file",
		}).Render(context.Background(), c.Response().Writer)
	}

	// Create new analysis job
	jobID := fmt.Sprintf("job_%d", timestamp)
	job := &models.AnalysisJob{
		ID:        jobID,
		Filename:  filename,
		Status:    "pending",
		StartTime: time.Now(),
	}

	// Store job
	jobsMutex.Lock()
	jobs[jobID] = job
	jobsMutex.Unlock()

	// Start analysis in background
	go analyzeFile(job, filePath)

	// Get list of files for display
	files := []home.UploadedFile{} // Get your files list here

	// Return success response
	return home.ShowHome(files, &home.UploadResponse{
		Status:  "success",
		Message: "File uploaded successfully",
	}).Render(context.Background(), c.Response().Writer)
}

// analyzeFile processes the uploaded PCAP file
func analyzeFile(job *models.AnalysisJob, filePath string) {
	// Update job status
	jobsMutex.Lock()
	job.Status = "processing"
	jobsMutex.Unlock()

	// Open the PCAP file
	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		log.Printf("Error opening PCAP file %s: %v", filePath, err)
		jobsMutex.Lock()
		job.Status = "error"
		job.ErrorMessage = "Failed to open PCAP file for analysis"
		jobsMutex.Unlock()
		return
	}
	defer handle.Close()

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Process packets
	var packetCount int64
	for packet := range packetSource.Packets() {
		if err := pcap.ProcessPacket(packet); err != nil {
			log.Printf("Error processing packet %d: %v", packetCount, err)
			// Continue processing other packets
		}
		packetCount++

		// Update job status periodically
		if packetCount%1000 == 0 {
			jobsMutex.Lock()
			job.TotalPackets = packetCount
			jobsMutex.Unlock()
		}
	}

	// Update final job status
	jobsMutex.Lock()
	job.Status = "completed"
	job.EndTime = time.Now()
	job.TotalPackets = packetCount
	jobsMutex.Unlock()

	// Clean up the uploaded file after processing
	go func() {
		time.Sleep(time.Hour) // Keep file for 1 hour
		if err := os.Remove(filePath); err != nil {
			log.Printf("Failed to remove processed file %s: %v", filePath, err)
		}
	}()
}
