package main

import (
	"casino-web3/config"
	"casino-web3/db"
	"casino-web3/handlers"
	"casino-web3/middleware"
	"log"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func DBinit() *gorm.DB {
	db, err := db.ConnectDB()
	if err != nil {
		log.Printf("Failed to connect to database: %v", err)
		return nil
	}

	return db
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	r := gin.Default()

	db := DBinit()

	server := handlers.NewServer(db)

	router := r.Group("/auth")
	r.Use(middleware.JwtAuthMiddleware())
	{
		router.POST("/register", server.RegisterUser)
		router.POST("/login", server.LoginUser)
	}

	if err := r.Run(":" + cfg.Server.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
