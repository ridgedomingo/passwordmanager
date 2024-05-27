package middleware

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

type CustomClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// JWT username value
var JwtUsername string

// Interceptor to check if requests have a valid jwt included
func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		key := os.Getenv("SECRET_KEY")
		secretKey := []byte(key)
		if key == "" {
			log.Print("SECRET_KEY environment variable is not set")
			return c.String(http.StatusInternalServerError, "Internal server error")
		}

		// Validate the JWT token here
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return c.String(http.StatusUnauthorized, "Authorization header missing")
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.String(http.StatusUnauthorized, "Invalid Authorization header")
		}

		tokenString := parts[1]

		// Validate JWT token
		token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Return the secret key for token validation
			return secretKey, nil
		})
		if err != nil {
			return c.String(http.StatusUnauthorized, "Invalid token: "+err.Error())
		}

		// Validate token claims
		if !token.Valid {
			return c.String(http.StatusUnauthorized, "Invalid token")
		}

		claims, ok := token.Claims.(*CustomClaims)
		if !ok || !token.Valid {
			return c.String(http.StatusUnauthorized, "Invalid JWT token")
		}
		JwtUsername = claims.Username

		c.Set("username", claims)
		// Call the next handler if the token is valid
		return next(c)
	}
}
