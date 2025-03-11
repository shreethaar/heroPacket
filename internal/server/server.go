// If there's any CSRF configuration here, remove it completely
// Keep other server configurations intact

// Example:
// Remove any lines like:
// server.Use(middleware.CSRF())
// or
// e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{...}))

// If this file exists and contains CSRF middleware, remove it 

// Set up routes
e.GET("/", userHandler.HandleIndex)
e.GET("/home", userHandler.HandleHome)
e.POST("/upload", userHandler.HandleUpload)
e.GET("/refresh-files", userHandler.HandleRefreshFiles)
e.DELETE("/delete-file/:filename", userHandler.HandleDeleteFile)
e.GET("/download/:filename", userHandler.HandleDownload)
e.GET("/documentation", userHandler.HandleDocumentation)
e.GET("/protocol-chart", userHandler.ProtocolChart)