package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/ridgedomingo/go-exercises/pkg/generator"
	"github.com/ridgedomingo/passwordmanager/internal/database"
)

// JWT username value
// var jwtUsername string

type PasswordGeneratorParams struct {
	Username string `json:"userName"`
	Url      string `json:"url"`
}

func encrypt(plaintext, salt string) (string, error) {
	returnString := ""
	var returnError error
	key, err := os.LookupEnv("AES_KEY")
	if !err {
		log.Print("Could not get env")
		returnError = errors.New("something went wrong")
	} else {

		block, err := aes.NewCipher([]byte(key))
		if err != nil {
			log.Print("Error encrypting", err)
			returnError = errors.New("something went wrong")
		}

		plaintextWithSalt := salt + plaintext

		ciphertext := make([]byte, aes.BlockSize+len(plaintextWithSalt))
		iv := ciphertext[:aes.BlockSize]
		if _, err := rand.Read(iv); err != nil {
			returnError = err
		}

		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintextWithSalt))

		returnString = base64.URLEncoding.EncodeToString(ciphertext)
	}
	return returnString, returnError
}

// Function handler for GET /credential/:username
//
// This will retrieve the user's saved credentials by providing the username
func GetUserCredentials(c echo.Context) error {
	username := c.Param("username")

	// if username != jwtUsername {
	// 	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	// 	return
	// }

	var userCredentials []database.UserCredentials
	if username != "" {
		err := database.DBCon.Where("username = ?", username).Find(&userCredentials).Error
		if err != nil {
			log.Print("Error while getting credentials", err)
			return c.String(http.StatusInternalServerError, "Error while getting credentials")
		}
	}

	// Create anonmyous struct to remove salt from response
	var response []interface{}
	for _, uc := range userCredentials {
		encryptedPassword, err := encrypt(uc.Password, uc.Salt)

		if err != nil {
			return c.String(http.StatusInternalServerError, "Something went wrong")
		}
		response = append(response, struct {
			Username  string    `json:"username"`
			Password  string    `json:"password"`
			Url       string    `json:"url"`
			CreatedAt time.Time `json:"created_at"`
		}{
			Username:  uc.Username,
			Password:  encryptedPassword, // Encrypt password with salt
			Url:       uc.Url,
			CreatedAt: uc.CreatedAt,
		})
	}
	return c.JSON(http.StatusOK, response)
}

// Function handler for POST /credential
//
// Function handler that saves user credentials in database
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
