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
			return c.Path() == "/static/*" || c.Path() == "/upload" || c.Request().Method == "DELETE"
		},
	}))

	// Configure body limit for file uploads (100MB)
	app.Use(middleware.BodyLimit("100MB"))

	// Routes
	userHandler := handler.NewUserHandler()
	app.GET("/", userHandler.HandleMainPage)
	//app.GET("/home", userHandler.HandleHomePage)
	app.POST("/upload", userHandler.HandleUpload)
	app.GET("/refresh-files", userHandler.HandleRefreshFiles)
	app.GET("/analytics/:filename", userHandler.HandleOverview)
	//app.GET("/docs", userHandler.HandleDocs)                  
	//app.GET("/protocol-chart/:sessionID", userHandler.ProtocolChart)
	//app.GET("/traffic-timeline/:sessionID", userHandler.TrafficTimeline)

	// Start server
	if err := app.Start(":8080"); err != nil {
		log.Fatal(err)
	}
}
