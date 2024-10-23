package main

import (
	"log"
	"net/http"

	"auth-service/internal/auth"
	"auth-service/internal/database"

	"github.com/go-chi/chi/v5"
)

func main() {
	database.InitDB()

	router := chi.NewRouter()
	router.Post("/auth/register", auth.Register)
	router.Post("/auth/getTokens", auth.GenerateTokenPair)
	router.Post("/auth/refreshTokens", auth.RefreshTokenHandler)
	router.Post("/auth/logoutOtherSessions", auth.LogoutOtherSessions)

	log.Println("Сервер запущен на порту 8080...")
	log.Fatal(http.ListenAndServe(":8080", router))
}
