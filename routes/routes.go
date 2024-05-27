package routes

import (
	"github.com/labstack/echo/v4"
	"github.com/ridgedomingo/passwordmanager/handlers"
	"github.com/ridgedomingo/passwordmanager/internal/middleware"
)

func NewRouter() *echo.Echo {
	e := echo.New()

	// Protected routes
	r := e.Group("/user")
	r.Use(middleware.AuthMiddleware)

	r.POST("/credential", handlers.SaveCredentials)

	r.GET("/credential/:username", handlers.GetUserCredentials)

	r.DELETE("/cache/:username", handlers.DeleteCacheByUsername)
	r.DELETE("/cache", handlers.DeleteCache)

	// public routes
	e.POST("/generate-token", handlers.GenerateJWT)

	return e
}
