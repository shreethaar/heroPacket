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
"

	"heroPacket/internal/models"
	"heroPacket/internal/pcap"
	"heroPacket/internal/templates/components"
	"heroPacket/internal/templates/layouts"
)

var (
	jobs      = make(map[string]*models.AnalysisJob)
	jobsMutex sync.RWMutex
)

// Home handles the root route
func Home(w http.ResponseWriter, r *http.Request) {
	if err := layouts.Base(components.Upload()).Render(context.Background(), w); err != nil {
		log.Printf("Error rendering home template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// UploadPCAP handles PCAP file uploads
func UploadPCAP(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB max
		log.Printf("Failed to parse multipart form: %v", err)
		http.Error(w, "Invalid file upload", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("pcap")
	if err != nil {
		log.Printf("Failed to get PCAP file: %v", err)
		http.Error(w, "Missing or invalid PCAP file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file extension
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".pcap") {
		http.Error(w, "Only .pcap files are allowed", http.StatusBadRequest)
		return
	}

	// Create uploads directory if it doesn't exist
	uploadsDir := "./uploads"
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		log.Printf("Failed to create uploads directory: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate unique filename
	timestamp := time.Now().Unix()
	filename := fmt.Sprintf("%d_%s", timestamp, filepath.Clean(header.Filename))
	filePath := filepath.Join(uploadsDir, filename)

	// Create destination file
	dst, err := os.Create(filePath)
	if err != nil {
		log.Printf("Failed to create destination file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy uploaded file
	if _, err = io.Copy(dst, file); err != nil {
		log.Printf("Failed to save uploaded file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		os.Remove(filePath) // Clean up partial file
		return
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

	// Render initial status
	if err := components.AnalysisStatus(job).Render(context.Background(), w); err != nil {
		log.Printf("Error rendering analysis status: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
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
