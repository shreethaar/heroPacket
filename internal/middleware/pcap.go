package middleware

import (
	"log"
    "crypto/md5"
	"bytes"
    "fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/labstack/echo/v4"
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
    Hash       string
}

// Store for keeping track of file hashes
var (
	fileHashes = make(map[string]string) // map[hash]filename
	hashMutex  sync.RWMutex
)


func ValidateAndSavePCAP(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Get file
		file, err := c.FormFile("file")
		if err != nil {
			log.Println("DEBUG: No file uploaded:", err)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "No file uploaded"})
		}

		// Validate file size
		if file.Size > 100*1024*1024 {
			log.Println("DEBUG: File too large:", file.Size)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "File size exceeds 100MB limit"})
		}

		// Open file
		src, err := file.Open()
		if err != nil {
			log.Println("DEBUG: Failed to open file:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to read file"})
		}
		defer src.Close()

		// Read first 14 bytes
		header := make([]byte, 14)
		_, err = src.Read(header)
		if err != nil {
			log.Println("DEBUG: Failed to read file header:", err)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Failed to read file header"})
		}

		// Print hex dump of header for debugging
		log.Printf("DEBUG: File header: %x\n", header)

		// Validate magic number for PCAP-NG
		if !bytes.Equal(header[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}) || 
		   !bytes.Equal(header[8:12], []byte{0x4d, 0x3c, 0x2b, 0x1a}) {
			log.Println("DEBUG: Invalid PCAP-NG magic number")
			return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Invalid file format. Expected a PCAP file."),
        })
		}

		// Reset file pointer before saving
		_, err = src.Seek(0, io.SeekStart)
		if err != nil {
			log.Println("DEBUG: Failed to reset file pointer:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to reset file pointer"})
		}

		// Create uploads directory
		if err := os.MkdirAll("uploads", 0755); err != nil {
			log.Println("DEBUG: Failed to create uploads directory:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create uploads directory"})
		}

		// Compute MD5 hash and save the file
		dstPath := filepath.Join("uploads", file.Filename)
		dst, err := os.Create(dstPath)
		if err != nil {
			log.Println("DEBUG: Failed to create destination file:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create destination file"})
		}
		defer dst.Close()

		hash := md5.New()
		if _, err = io.Copy(io.MultiWriter(dst, hash), src); err != nil {
			os.Remove(dstPath) // Cleanup on error
			log.Println("DEBUG: Failed to save file:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to save file"})
		}

		// Convert hash to string
		hashStr := fmt.Sprintf("%x", hash.Sum(nil))

		// Store the processed file info
		pcapFile := PCAPFile{
			Path: dstPath,
			Hash: hashStr,
		}

		// Store in context for next handler
		c.Set("pcapFile", pcapFile)

		log.Println("DEBUG: File successfully uploaded:", dstPath)

		// Proceed to next handler
		return next(c)
	}
}

// Helper function to render responses
func render(c echo.Context, data interface{}) error {
	return c.JSON(http.StatusOK, data)
}

// PCAPValidator is a middleware that validates PCAP files

