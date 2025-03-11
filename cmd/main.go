package main

import (
	"heroPacket/handler"
	"log"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	app := echo.New()
	// Middleware
	app.Use(middleware.Logger())
	app.Use(middleware.Recover())
	app.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLength:  32,
		TokenLookup:  "form:_csrf",
		CookieName:   "csrf",
		CookieMaxAge: 86400,
		Skipper: func(c echo.Context) bool {
			return c.Path() == "/static/*" || c.Path() == "/upload" // Skip CSRF for upload endpoint
		},
	}))
	// Routes
	userHandler := handler.NewUserHandler()
	app.GET("/", userHandler.HandleHomePage) // Changed to show dashboard on root
	//app.GET("/welcome", userHandler.HandleMainPage)  // Moved welcome page to /welcome
	app.POST("/upload", userHandler.HandleUpload)
	// Analysis routes
	app.GET("/analyze/:filename", userHandler.HandleAnalyze)
	app.GET("/overview/:filename", userHandler.HandleOverview)
	app.GET("/analytics/:filename", userHandler.HandleAnalytics)
	// Analysis visualization routes
	app.GET("/analysis/protocol-chart/:filename", userHandler.ProtocolChart)
	app.GET("/analysis/traffic-timeline/:filename", userHandler.TrafficTimeline)
	// Documentation route
	app.GET("/docs", userHandler.HandleDocs)
	// Start server
	log.Println("Server starting on :9999")
	app.Logger.Fatal(app.Start(":9999"))
}
