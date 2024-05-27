package handlers

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

// Parameters to be passed for POST /credentials
//
// This will generate jwt token that will expire in 1 day.
type GenerateJWTParams struct {
	Username string `json:"userName"`
}

func GenerateJWT(c echo.Context) error {
	key := os.Getenv("SECRET_KEY")
	secretKey := []byte(key)

	params := new(GenerateJWTParams)
	if err := c.Bind(params); err != nil {
		log.Print("Error while decoding json ", err)
		return c.String(http.StatusInternalServerError, "Internal Server error")
	}

	if key == "" {
		log.Print("SECRET_KEY environment variable is not set")
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}

	claims := jwt.MapClaims{
		"username": params.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Token expiry time (1 day)
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		log.Print("Could not generate token", err)
	}
	return c.String(http.StatusOK, signedToken)
}
