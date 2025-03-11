package middleware

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"heroPacket/view/home"
)

// Constants for PCAP validation
const (
	MaxPCAPSize   = 100 * 1024 * 1024 // 100MB
	PCAPMagicLE   = "\xd4\xc3\xb2\xa1" // Little-endian
	PCAPMagicBE   = "\xa1\xb2\xc3\xd4" // Big-endian
	PCAPMagicNS   = "\x0a\x0d\x0d\x0a" // PCAPNG format
	UploadsDir    = "uploads"
)

type PCAPFile struct {
	FileHeader *multipart.FileHeader
	File       multipart.File
	Path       string
}

// Store for keeping track of file hashes
var (
	fileHashes = make(map[string]string) // map[hash]filename
	hashMutex  sync.RWMutex
)

func ValidateAndSavePCAP(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Get the file from the request
		file, err := c.FormFile("pcap-file")
		if err != nil {
			return render(c, home.UploadResponse{
				Status:  "error",
				Message: "No file uploaded",
			})
		}

		// Check file size
		if file.Size > MaxPCAPSize {
			return render(c, home.UploadResponse{
				Status:  "error",
				Message: "File size exceeds the allowed limit",
			})
		}

		// Open file
		src, err := file.Open()
		if err != nil {
			return render(c, home.UploadResponse{
				Status:  "error",
				Message: fmt.Sprintf("Failed to open file: %v", err),
			})
		}
		defer src.Close()

		// Read first 24 bytes for validation
		header := make([]byte, 24)
		if _, err := io.ReadFull(src, header); err != nil {
			return render(c, home.UploadResponse{
				Status:  "error",
				Message: "Invalid file format",
			})
		}

		// Validate magic number
		magicNum := string(header[:4])
		if magicNum != PCAPMagicLE && magicNum != PCAPMagicBE && magicNum != PCAPMagicNS {
			return render(c, home.UploadResponse{
				Status:  "error",
				Message: "Invalid PCAP file format",
			})
		}

		// Create a hash of the remaining content
		hash := md5.New()
		if _, err := io.Copy(hash, src); err != nil {
			return render(c, home.UploadResponse{
				Status:  "error",
				Message: "Failed to calculate file hash",
			})
		}
		fileHash := hex.EncodeToString(hash.Sum(nil))

		// Check for duplicate file
		hashMutex.RLock()
		if existingFile, exists := fileHashes[fileHash]; exists {
			hashMutex.RUnlock()
			return render(c, home.UploadResponse{
				Status:  "error",
				Message: fmt.Sprintf("Duplicate file detected. Already uploaded as: %s", existingFile),
			})
		}
		hashMutex.RUnlock()

		// Reset file pointer to save the file
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			return render(c, home.UploadResponse{
				Status:  "error",
				Message: "Failed to process file",
			})
		}

		// Ensure uploads directory exists
		if err := os.MkdirAll(UploadsDir, 0755); err != nil {
			return render(c, home.UploadResponse{
				Status:  "error",
				Message: fmt.Sprintf("Failed to create uploads directory: %v", err),
			})
		}

		// Generate a unique filename
		uniqueFilename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(file.Filename))
		dstPath := filepath.Join(UploadsDir, uniqueFilename)

		// Save file
		dst, err := os.Create(dstPath)
		if err != nil {
			return render(c, home.UploadResponse{
				Status:  "error",
				Message: fmt.Sprintf("Failed to save file: %v", err),
			})
		}
		defer dst.Close()

		if _, err := io.Copy(dst, src); err != nil {
			return render(c, home.UploadResponse{
				Status:  "error",
				Message: fmt.Sprintf("Failed to copy file: %v", err),
			})
		}

		// Store hash after validation
		hashMutex.Lock()
		fileHashes[fileHash] = uniqueFilename
		hashMutex.Unlock()

		// Set file info in context for next handler
		c.Set("pcapFile", PCAPFile{
			FileHeader: file,
			Path:       dstPath,
		})

		return next(c)
	}
}
// Helper function to render responses
func render(c echo.Context, data interface{}) error {
	return c.JSON(http.StatusOK, data)
}

// PCAPValidator is a middleware that validates PCAP files

