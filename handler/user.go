package handler

import (
    "github.com/labstack/echo/v4"
    "heroPacket/view/home"
    "heroPacket/view/upload"
    "heroPacket/internal/pcap"
    "io"
    "net/http"
    "os"
    "fmt"
)

type UserHandler struct {
}

func (h UserHandler) HandleHomePage(c echo.Context) error {
    return render(c, home.Show())
}

func (h UserHandler) HandleUploadPage(c echo.Context) error {
    if c.Request().Method == http.MethodGet {
        return render(c, upload.Show(nil, ""))
    }

    file, err := c.FormFile("pcap-file")
    if err != nil {
        return render(c, upload.Show(nil, "Failed to get uploaded file"))
    }

    src, err := file.Open()
    if err != nil {
        return render(c, upload.Show(nil, "Failed to open uploaded file"))
    }
    defer src.Close()

    os.MkdirAll("./uploads", os.ModePerm)
    dstPath := "./uploads/" + file.Filename
    dst, err := os.Create(dstPath)
    if err != nil {
        return render(c, upload.Show(nil, "Failed to save uploaded file"))
    }
    defer dst.Close()

    if _, err := io.Copy(dst, src); err != nil {
        return render(c, upload.Show(nil, "Failed to copy file"))
    }

    packets, err := pcap.ProcessPCAP(dstPath)
    if err != nil {
        return render(c, upload.Show(nil, "Failed to process PCAP"))
    }

    // Convert PacketInfo slice to string slice using the updated field names
    packetStrings := make([]string, len(packets))
    for i, p := range packets {
        packetStrings[i] = fmt.Sprintf("Source: %s, Destination: %s, Protocol: %s, Length: %d bytes", 
            p.SourceIP, p.DestIP, p.Protocol, p.Length)
    }

    return render(c, upload.Show(packetStrings, "Upload successful!"))
}
