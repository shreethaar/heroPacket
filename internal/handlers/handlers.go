// YOU FUCK HEAD, CHANGE THIS, YOU JUST COPY & PASTE, YOU LAZY FUCK

package handlers

import (
    "context"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "sync"
    "time"
    
    "github.com/go-chi/chi/v5"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    
    "heroPacket/internal/models"
    "heroPacket/internal/pcap"
    "heroPacket/internal/templates/components"
    "heroPacket/internal/templates/layouts"
)

/*
// AnalysisJob represents a PCAP analysis job
type AnalysisJob struct {
    ID            string
    Filename      string
    Status        string // "pending", "processing", "completed", "error"
    ErrorMessage  string
    StartTime     time.Time
    EndTime       time.Time
    PacketStats   *pcap.PacketStats
    TotalPackets  int64
}
*/


var (
    jobs = make(map[string]*AnalysisJob)
    jobsMutex sync.RWMutex
)

// Home handles the root route
func Home(w http.ResponseWriter, r *http.Request) {
    err := layouts.Base(components.Upload()).Render(context.Background(), w)
    if err != nil {
        http.Error(w, "Error rendering template", http.StatusInternalServerError)
        return
    }
}

// UploadPCAP handles PCAP file uploads
func UploadPCAP(w http.ResponseWriter, r *http.Request) {
    // Parse multipart form
    err := r.ParseMultipartForm(32 << 20) // 32MB max
    if err != nil {
        http.Error(w, "Failed to parse form", http.StatusBadRequest)
        return
    }

    file, header, err := r.FormFile("pcap")
    if err != nil {
        http.Error(w, "Failed to get file", http.StatusBadRequest)
        return
    }
    defer file.Close()

    // Create uploads directory if it doesn't exist
    uploadsDir := "./uploads"
    os.MkdirAll(uploadsDir, os.ModePerm)

    // Generate unique filename
    timestamp := time.Now().Unix()
    filename := fmt.Sprintf("%d_%s", timestamp, header.Filename)
    filepath := filepath.Join(uploadsDir, filename)

    // Create destination file
    dst, err := os.Create(filepath)
    if err != nil {
        http.Error(w, "Failed to create file", http.StatusInternalServerError)
        return
    }
    defer dst.Close()

    // Copy uploaded file
    _, err = io.Copy(dst, file)
    if err != nil {
        http.Error(w, "Failed to save file", http.StatusInternalServerError)
        return
    }

    // Create new analysis job
    jobID := fmt.Sprintf("job_%d", timestamp)
    job := &AnalysisJob{
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
    go analyzeFile(job, filepath)

    // Render initial status
    err = components.AnalysisStatus(job).Render(context.Background(), w)
    if err != nil {
        http.Error(w, "Error rendering template", http.StatusInternalServerError)
        return
    }
}

// GetStatus returns the current status of an analysis job
func GetStatus(w http.ResponseWriter, r *http.Request) {
    jobID := chi.URLParam(r, "id")
    
    jobsMutex.RLock()
    job, exists := jobs[jobID]
    jobsMutex.RUnlock()
    
    if !exists {
        http.Error(w, "Job not found", http.StatusNotFound)
        return
    }

    err := components.AnalysisStatus(job).Render(context.Background(), w)
    if err != nil {
        http.Error(w, "Error rendering template", http.StatusInternalServerError)
        return
    }
}

// GetResults returns the analysis results for a completed job
func GetResults(w http.ResponseWriter, r *http.Request) {
    jobID := chi.URLParam(r, "id")
    
    jobsMutex.RLock()
    job, exists := jobs[jobID]
    jobsMutex.RUnlock()
    
    if !exists {
        http.Error(w, "Job not found", http.StatusNotFound)
        return
    }

    if job.Status != "completed" {
        http.Error(w, "Analysis not completed", http.StatusBadRequest)
        return
    }

    err := components.AnalysisResults(job).Render(context.Background(), w)
    if err != nil {
        http.Error(w, "Error rendering template", http.StatusInternalServerError)
        return
    }
}

// analyzeFile processes the uploaded PCAP file
func analyzeFile(job *AnalysisJob, filepath string) {
    // Update job status
    jobsMutex.Lock()
    job.Status = "processing"
    jobsMutex.Unlock()

    // Open the PCAP file
    handle, err := pcap.OpenOffline(filepath)
    if err != nil {
        jobsMutex.Lock()
        job.Status = "error"
        job.ErrorMessage = fmt.Sprintf("Error opening PCAP: %v", err)
        jobsMutex.Unlock()
        return
    }
    defer handle.Close()

    // Create packet source
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    // Process packets
    var packetCount int64
    for packet := range packetSource.Packets() {
        pcap.ProcessPacket(packet)
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
        os.Remove(filepath)
    }()
}

// Cleanup removes old jobs periodically
func StartCleanup() {
    go func() {
        for {
            time.Sleep(time.Hour)
            cleanup()
        }
    }()
}

func cleanup() {
    threshold := time.Now().Add(-24 * time.Hour)
    
    jobsMutex.Lock()
    for id, job := range jobs {
        if !job.EndTime.IsZero() && job.EndTime.Before(threshold) {
            delete(jobs, id)
        }
    }
    jobsMutex.Unlock()
}
