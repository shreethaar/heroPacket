package handler

import (
    "github.com/labstack/echo/v4"
    "heroPacket/view/home"
    "heroPacket/view/upload"
)

type UserHandler struct {

}

func (h UserHandler) HandleHomePage(c echo.Context) error {
    return render(c, home.Show())
}

func (h UserHandler) HandleUploadPage(c echo.Context) error {
    return render(c, upload.Show())
}

/*
func(h UserHandler) HandleUserShow(c echo.Context) error {
    return render(c, user.Show())
}
*/
