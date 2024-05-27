package routes

import (
	"github.com/labstack/echo/v4"
	"github.com/ridgedomingo/passwordmanager/handlers" // Adjust the import path accordingly
)

func NewRouter() *echo.Echo {
	e := echo.New()

	// Define your routes here
	e.GET("/credential/:username", handlers.GetUserCredentials)

	e.POST("/credential", handlers.SaveCredentials)
	return e
}
