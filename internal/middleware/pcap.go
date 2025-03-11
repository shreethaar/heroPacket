package middleware

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/labstack/echo"
)

type PCAPFile struct {
	FileHeader *multipart.FileHeader
	File       multipart.File
	Path       string
}

func ValidateAndSavePCAP(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Validate file upload
		file, err := c.FormFile("pcap-file")
		if err != nil {
			return c.String(http.StatusBadRequest, "No file uploaded")
		}

		// Check file size
		if file.Size > MaxPCAPSize {
			return c.String(http.StatusBadRequest, "File size exceeds the allowed limit")
		}

		// Open file
		src, err := file.Open()
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to open file: %v", err))
		}
		defer src.Close()

		// Validate magic number
		header := make([]byte, 24)
		if _, err := io.ReadFull(src, header); err != nil {
			return c.String(http.StatusBadRequest, "Invalid file format")
		}
		if !bytes.Equal(header[:4], []byte(PCAPMagicLE)) &&
			!bytes.Equal(header[:4], []byte(PCAPMagicBE)) &&
			!bytes.Equal(header[:4], []byte(PCAPMagicNS)) {
			return c.String(http.StatusBadRequest, "Invalid PCAP file signature")
		}

		// Reset file reader
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to reset file reader: %v", err))
		}

		// Ensure uploads directory exists
		if err := os.MkdirAll(UploadsDir, 0755); err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to create uploads directory: %v", err))
		}

		// Generate a unique filename
		uniqueFilename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(file.Filename))
		dstPath := filepath.Join(UploadsDir, uniqueFilename)

		// Save file
		dst, err := os.Create(dstPath)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to save file: %v", err))
		}
		defer dst.Close()

		if _, err := io.Copy(dst, src); err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to copy file: %v", err))
		}

		// Attach file info to context
		c.Set("pcapFile", PCAPFile{
			FileHeader: file,
			File:       src,
			Path:       dstPath,
		})

		return next(c)
	}
}

// PCAPValidator is a middleware that validates PCAP files
func PCAPValidator() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Only apply to POST requests to /upload
			if c.Request().Method != http.MethodPost || c.Path() != "/upload" {
				return next(c)
			}

			// The constants are now defined in middleware.go, so we can use them directly
			// MaxPCAPSize, PCAPMagicLE, PCAPMagicBE, PCAPMagicNS

			return next(c)
		}
	}
}
