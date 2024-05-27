package routes

import (
	"github.com/labstack/echo/v4"
	"github.com/ridgedomingo/passwordmanager/handlers" // Adjust the import path accordingly
)

func NewRouter() *echo.Echo {
	e := echo.New()

	// Define your routes here
	e.POST("/credential", handlers.SaveCredentials)
	return e
}
