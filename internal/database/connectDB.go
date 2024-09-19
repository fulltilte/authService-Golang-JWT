package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	_ "github.com/lib/pq"
)

type Config struct {
	DBUser     string `json:"db_user"`
	DBPassword string `json:"db_password"`
	DBName     string `json:"db_name"`
	DBSSLMode  string `json:"db_sslmode"`
}

var DB *sql.DB

func LoadConfig(file string) (Config, error) {
	var config Config
	configFile, _ := os.Open(file)

	defer configFile.Close()

	byteValue, _ := io.ReadAll(configFile)
	json.Unmarshal(byteValue, &config)

	return config, nil
}

func init() {
    config, _ := LoadConfig("config.json")

    dsn := fmt.Sprintf("user=%s dbname=%s password=%s sslmode=%s host=%s port=%d",
        config.DBUser, config.DBName, config.DBPassword, config.DBSSLMode, "postgres-dev", 5432)

    var err error
    DB, err = sql.Open("postgres", dsn)
    if err != nil {
        log.Fatalf("Error connecting to the database: %v", err)
    }

    if err = DB.Ping(); err != nil {
        log.Fatalf("Error pinging the database: %v", err)
    }
    fmt.Println("Database connected successfully")
}