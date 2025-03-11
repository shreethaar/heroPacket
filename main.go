package main

import (
	"heroPacket/handler"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

func main() {
	// Create a new Echo instance
	e := echo.New()

	// Add only the middleware we want
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// No CSRF middleware

	// Initialize user handler
	userHandler := handler.NewUserHandler()

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

	// Start server
	e.Start(":8080")
}
