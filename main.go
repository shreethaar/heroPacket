package main

import (
	"heroPacket/handler"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

// Register routes
func registerRoutes(e *echo.Echo, userHandler *handler.UserHandler) {
	// Apply middleware to all routes
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CSRF())

	// Public routes
	e.GET("/", userHandler.HandleMainPage)
	e.GET("/home", userHandler.HandleHomePage)
	e.GET("/documentation", userHandler.HandleDocs)

	// File upload route with PCAP validation middleware
	e.POST("/upload", userHandler.HandleUpload)

	// Analysis routes
	e.GET("/analyze/:filename", userHandler.HandleAnalyze)
	e.GET("/overview/:filename", userHandler.HandleOverview)
	e.GET("/analytics/:filename", userHandler.HandleAnalytics)

	// Serve static files
	e.Static("/static", "static")
}

func main() {
	e := echo.New()
	userHandler := &handler.UserHandler{}
	registerRoutes(e, userHandler)
	e.Start(":8080")
}
