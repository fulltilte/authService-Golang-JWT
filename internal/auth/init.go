package auth

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

var JwtKey []byte

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Ошибка загрузки .env файла: %s", err)
	}
	JwtKey = []byte(os.Getenv("SECRET_KEY"))
}
