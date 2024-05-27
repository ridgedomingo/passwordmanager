package database

import (
	"fmt"
	"time"

	_ "github.com/lib/pq" // Import PostgreSQL driver
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	DBCon    *gorm.DB
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "Postgres!!"
	dbname   = "postgres"
)

// UserCredentials Schema
type UserCredentials struct {
	Username  string    `json:"username"`
	Url       string    `json:"url"`
	Password  string    `json:"password"`
	Salt      string    `json:"salt"`
	CreatedAt time.Time `json:"created_at"`
}

func CreateConnection() (*gorm.DB, error) {
	connectionString := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	// PostgreSQL connection string
	// // Open the PostgreSQL database connection
	// db, err := sql.Open("postgres", connectionString)
	db, err := gorm.Open(postgres.Open(connectionString), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	// Ensure the database connection is still alive
	// if err := db.Ping(); err != nil {
	// 	return nil, err
	// }
	return db, nil
}
