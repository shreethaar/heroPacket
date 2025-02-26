package handler

import (
    "context"
    "fmt"
    "net/http"
    "sync"
    "time"

    "github.com/google/uuid"
    "github.com/labstack/echo/v4"
    "heroPacket/internal/analysis"
    "heroPacket/internal/middleware"
    "heroPacket/view/home"
    "heroPacket/view/upload"
)

type UserHandler struct {
    analysisCache map[string]*analysis.Session
    cacheMutex    sync.RWMutex
}

func NewUserHandler() *UserHandler {
    return &UserHandler{
        analysisCache: make(map[string]*analysis.Session),
    }
}

func (h *UserHandler) HandleHomePage(c echo.Context) error {
    return render(c, home.Show())
}

func (h *UserHandler) HandleUploadPage(c echo.Context) error {
    if c.Request().Method == http.MethodGet {
        return render(c, upload.Show(upload.ViewData{}))
    }

    // Retrieve validated file
    pcapFile, ok := c.Get("pcapFile").(middleware.PCAPFile)
    if !ok {
        return render(c, upload.Show(upload.ViewData{
            Error: "Failed to retrieve PCAP file",
        }))
    }

    // Process PCAP using analysis package
    packets, err := analysis.ExtractPackets(pcapFile.Path)
    if err != nil {
        return render(c, upload.Show(upload.ViewData{
            Error: "PCAP processing failed: " + err.Error(),
        }))
    }

    // Create analysis session
    sessionID := uuid.New().String()
    session := analysis.NewSession()
    
    // Process packets concurrently
    var wg sync.WaitGroup
    for _, packet := range packets {
        wg.Add(1)
        go func(p models.Packet) {
            defer wg.Done()
            session.Process(p)
        }(packet)
    }
    wg.Wait()

    // Store session in cache
    h.cacheMutex.Lock()
    h.analysisCache[sessionID] = session
    h.cacheMutex.Unlock()

    // Set cache expiration
    go h.clearCacheAfter(sessionID, 30*time.Minute)

    // Prepare view data
    viewData := upload.ViewData{
        SessionID:    sessionID,
        PacketCount:  len(packets),
        TopProtocols: session.Protocols().Top(3),
        TrafficStats: session.TrafficStats(),
        Conversations: session.Conversations().Top(5),
    }

    return render(c, upload.ShowResults(viewData))
}
// HTMX Handlers for visualizations
func (h *UserHandler) ProtocolChart(c echo.Context) error {
    sessionID := c.Param("sessionID")
    
    h.cacheMutex.RLock()
    session, exists := h.analysisCache[sessionID]
    h.cacheMutex.RUnlock()
    
    if !exists {
        return c.String(http.StatusNotFound, "Session expired")
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
        return c.String(http.StatusNotFound, "Session expired")
    }

    c.Response().Header().Set(echo.HeaderContentType, "image/svg+xml")
    return session.TrafficTimeline().Render(c.Response().Writer)
}

func (h *UserHandler) clearCacheAfter(sessionID string, duration time.Duration) {
    time.Sleep(duration)
    h.cacheMutex.Lock()
    delete(h.analysisCache, sessionID)
    h.cacheMutex.Unlock()
}
