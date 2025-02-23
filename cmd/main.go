package main

import (
    "github.com/labstack/echo/v4"
    "heroPacket/handler"
)



func main() {
    app:=echo.New()
    /*app.GET("/", func(c echo.Context) error {
        return c.String(http.StatusOK,"Hello, world!")
    })*/

    //app.GET("/user",handler.)

    userHandler:=handler.UserHandler{}
    app.GET("/user",userHandler.HandleUserShow)
    app.Logger.Fatal(app.Start(":1323"))

}

