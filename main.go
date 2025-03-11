package main

import (
	"heroPacket/handler"
	"net/http"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

func main() {
	// Create a new Echo instance with custom configuration
	e := echo.New()

	// Disable CSRF by setting a custom HTTP error handler that ignores CSRF errors
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		// Check if it's a CSRF error
		if err != nil && err.Error() == "missing csrf token in the form parameter" {
			// Ignore CSRF errors and continue processing the request
			c.Response().WriteHeader(http.StatusOK)
			return
		}

		// For other errors, use the default error handler
		e.DefaultHTTPErrorHandler(err, c)
	}

	// Add only the essential middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// NO CSRF middleware

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
	e.DELETE("/delete-file/:filename", userHandler.HandleDeleteFile)
	e.GET("/refresh-files", userHandler.HandleRefreshFiles)

	// Analysis routes
	e.GET("/overview/:filename", userHandler.HandleOverview)
	e.GET("/analytics/:filename", userHandler.HandleAnalytics)

	// Serve static files
	e.Static("/static", "static")

	// Start server
	e.Start(":8080")
}
