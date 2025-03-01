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
			return c.Path() == "/static/*"
		},
	}))

	// Routes
	userHandler := handler.NewUserHandler()
	app.GET("/", userHandler.HandleMainPage)
	app.GET("/home", userHandler.HandleHomePage)
	app.POST("/upload", userHandler.HandleUpload)

	// Analytics and Overview routes
	app.GET("/analytics", userHandler.HandleAnalytics)
	app.GET("/overview", userHandler.HandleOverview)
	app.GET("/analytics/:sessionID", userHandler.HandleAnalytics)
	app.GET("/overview/:sessionID", userHandler.HandleOverview)

	// Documentation route
	app.GET("/docs", userHandler.HandleDocs)

	// Analysis visualization routes
	app.GET("/analysis/protocol-chart/:sessionID", userHandler.ProtocolChart)
	app.GET("/analysis/traffic-timeline/:sessionID", userHandler.TrafficTimeline)

	// Start server
	log.Println("Server starting on :3000")
	app.Logger.Fatal(app.Start(":3000"))
}
