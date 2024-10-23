package auth

import (
	"encoding/json"
	"log"
	"net/http"

	"auth-service/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type RegisterInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func Register(w http.ResponseWriter, r *http.Request) {
	var input RegisterInput

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Printf("(Register) Ошибка декодирования JSON: %v", err)
		handleError(w, "Ошибка декодирования JSON", http.StatusBadRequest)
		return
	}

	_, err := storage.GetUserByEmail(input.Email)
	if err == nil {
		log.Printf("(Register) Пользователь уже существует: %v", err)
		handleError(w, "Пользователь уже существует", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("(Register) Ошибка хэширования пароля: %v", err)
		handleError(w, "Ошибка хэширования пароля", http.StatusInternalServerError)
		return
	}

	err = storage.CreateUser(input.Email, string(hashedPassword))
	if err != nil {
		log.Printf("(Register) Ошибка создания пользователя: %v", err)
		handleError(w, "Ошибка создания пользователя", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully"))
}

func CheckPassword(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
