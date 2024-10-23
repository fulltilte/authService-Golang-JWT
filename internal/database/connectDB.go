package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
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

func LoadConfig() (Config, error) {
	configFile, err := os.Open("config.json")
	if err != nil {
		return Config{}, err
	}
	defer configFile.Close()

	var config Config
	err = json.NewDecoder(configFile).Decode(&config)
	return config, err
}

func InitDB() {
	config, err := LoadConfig()
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации БД: %s", err)
	}

	dsn := fmt.Sprintf("user=%s dbname=%s password=%s sslmode=%s host=%s port=%d",
		config.DBUser, config.DBName, config.DBPassword, config.DBSSLMode, "postgres-dev", 5432)

	DB, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Ошибка подключения к БД: %v", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatalf("Ошибка подключения к БД: %v", err)
	}

	log.Println("Подключение к БД успешно")
}
