package handler

import (
	"github.com/a-h/templ"
	"github.com/labstack/echo/v4"
)

// render is a helper function to render templ components with Echo
func render(c echo.Context, component templ.Component) error {
	return component.Render(c.Request().Context(), c.Response().Writer)
}
