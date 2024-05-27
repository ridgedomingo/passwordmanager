package main

import (
	"log"

	"github.com/ridgedomingo/passwordmanager/internal/database"
	"github.com/ridgedomingo/passwordmanager/routes"
)

func main() {
	database.DBCon, _ = database.CreateConnection()
	database.DBCon.AutoMigrate(&database.UserCredentials{})
	e := routes.NewRouter()
	if err := e.Start(":8080"); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
