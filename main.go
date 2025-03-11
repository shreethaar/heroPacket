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
	// CSRF middleware completely removed

	// Public routes
	e.GET("/", userHandler.HandleMainPage)
	e.GET("/home", userHandler.HandleHomePage)
	e.GET("/documentation", userHandler.HandleDocs)

	// File upload routes
	e.GET("/upload", userHandler.HandleUpload)
	e.POST("/upload", userHandler.HandleUpload)
	e.GET("/analyze/:filename", userHandler.HandleAnalyze)
	e.DELETE("/delete/:filename", userHandler.HandleDeleteFile)

	// Analysis routes
	e.GET("/overview/:filename", userHandler.HandleOverview)
	e.GET("/analytics/:filename", userHandler.HandleAnalytics)

	// Serve static files
	e.Static("/static", "static")
}

func main() {
	e := echo.New()
	userHandler := handler.NewUserHandler() // Use the constructor to properly initialize
	registerRoutes(e, userHandler)
	e.Start(":8080")
}
