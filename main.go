package main

import (
	"auth-service/internal/auth"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"
)

func main() {
	router := chi.NewRouter()
	router.Post("/auth/getTokens/{userID}", auth.GenerateTokenPair)
	router.Post("/auth/refreshTokens/{user_id}/{refresh_token}", auth.RefreshTokenHandler)

	log.Println("Сервер запущен...")
	log.Fatal(http.ListenAndServe(":8080", router))
}