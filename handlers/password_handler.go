package handlers

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"

	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/ridgedomingo/go-exercises/pkg/generator"
	"github.com/ridgedomingo/passwordmanager/internal/database"
)

// JWT username value
// var jwtUsername string

type PasswordGeneratorParams struct {
	Username string `json:"userName"`
	Url      string `json:"url"`
}

func SaveCredentials(c echo.Context) error {
	params := new(PasswordGeneratorParams)
	if err := c.Bind(params); err != nil {
		log.Print("Error while decoding json ", err)
		return c.String(http.StatusInternalServerError, "Internal Server error")
	}

	// if params.Username != jwtUsername {
	// 	return c.String(http.StatusUnauthorized, "Unauthorized")
	// }

	if params.Username == "" {
		return c.String(http.StatusBadRequest, "Username is missing in the request body")
	}

	if params.Url == "" {
		return c.String(http.StatusBadRequest, "Url is missing in the request body")
	}

	passwordParams := generator.PasswordParams{
		Length:              20,
		PasswordType:        "random",
		IsNumbersIncluded:   true,
		IsUppercaseIncluded: true,
		IsSymbolsIncluded:   true,
	}

	salt, _ := generateSalt(16)

	password := generator.GeneratePassword(passwordParams)
	hashedPassword := hashPassword(password, salt)

	// Insert user credentials into the database
	userCredential := database.UserCredentials{
		Username: params.Username,
		Password: hashedPassword,
		Url:      params.Url,
		Salt:     salt,
	}

	result := database.DBCon.Create(&userCredential)
	if result.Error != nil {
		log.Println("Failed to insert user credentials into database:", result.Error)
		return c.String(http.StatusInternalServerError, "Failed to insert user credentials into database")
	}

	return c.String(http.StatusOK, "Credentials successfully saved")
}

func generateSalt(length int) (string, error) {
	// Calculate the number of bytes needed for the salt
	numBytes := length * 3 / 4 // Base64 encoding expands 3 bytes to 4 characters

	// Generate random bytes for the salt
	saltBytes := make([]byte, numBytes)
	_, err := rand.Read(saltBytes)
	if err != nil {
		return "", err
	}

	salt := base64.RawURLEncoding.EncodeToString(saltBytes)

	// Truncate the salt to the desired length
	if len(salt) > length {
		salt = salt[:length]
	}

	return salt, nil
}

func hashPassword(password, salt string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password + salt))
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}
