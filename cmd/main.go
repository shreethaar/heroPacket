package main

import (
	"log"
    "heroPacket/handler"
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

	// Static files
	app.Static("/static", "internal/static")

	// Routes
	userHandler := handler.NewUserHandler()
	app.GET("/", userHandler.HandleHomePage)
	app.GET("/upload", userHandler.HandleUploadPage)
	app.POST("/upload", userHandler.HandleUploadPage)

	// Start server
	log.Println("Server starting on :3000")
	app.Logger.Fatal(app.Start(":3000"))
}
