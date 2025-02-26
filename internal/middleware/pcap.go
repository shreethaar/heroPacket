package middleware

import (
    "bytes"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "mime/multipart"

    "github.com/labstack/echo/v4"
)

const (
    //PCAPMagic    = "\xd4\xc3\xb2\xa1" // Little-endian magic number
    PCAPMagicLE  = "\xd4\xc3\xb2\xa1"
	PCAPMagicBE  = "\xa1\xb2\xc3\xd4"
	PCAPMagicNS  = "\xa1\xb2\x3c\x4d"
    MaxPCAPSize  = 100 * 1024 * 1024  // 100MB
    UploadsDir   = "./uploads"
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

        // Open file
        src, err := file.Open()
        if err != nil {
            return c.String(http.StatusInternalServerError, "Failed to open file")
        }
        defer src.Close()

        // Validate magic number
        header := make([]byte, 24)
        if _, err := io.ReadFull(src, header); err != nil {
            return c.String(http.StatusBadRequest, "Invalid file format")
        }
        if bytes.Equal(header[:4], []byte(PCAPMagicLE)) && 
            bytes.Equal(header[:4], []byte(PCAPMagicBE)) &&
             bytes.Equal(header[:4], []byte(PCAPMagicNS)) {
            return c.String(http.StatusBadRequest, "Invalid PCAP file signature")
        }

        // Save file
        os.MkdirAll(UploadsDir, os.ModePerm)
        dstPath := filepath.Join(UploadsDir, filepath.Base(file.Filename))
        dst, err := os.Create(dstPath)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Failed to save file")
        }
        defer dst.Close()

        if _, err := src.Seek(0, io.SeekStart); err != nil {
            return c.String(http.StatusInternalServerError, "Failed to reset file reader")
        }

        if _, err := io.Copy(dst, src); err != nil {
            return c.String(http.StatusInternalServerError, "Failed to copy file")
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
