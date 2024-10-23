package storage

import (
	"auth-service/internal/database"
	"database/sql"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       string
	Email    string
	Password string
}

func CreateUser(email, hashedPassword string) error {
	_, err := database.DB.Exec(
		"INSERT INTO users (email, password) VALUES ($1, $2)",
		email, hashedPassword,
	)
	return err
}

func GetUserByEmail(email string) (User, error) {
	var user User
	err := database.DB.QueryRow("SELECT id, email, password FROM users WHERE email = $1", email).Scan(&user.ID, &user.Email, &user.Password)
	return user, err
}

func StoreRefreshTokenInDB(refreshToken []byte, userID, userAgent, ipAddress string) error {
	var existingTokenHash string

	err := database.DB.QueryRow(
		"SELECT token_hash FROM refresh_tokens WHERE user_id = $1 AND user_agent = $2",
		userID, userAgent,
	).Scan(&existingTokenHash)

	if err != nil && err != sql.ErrNoRows {
		return err
	}

	if err == nil {
		return fmt.Errorf("Такая сессия уже существует")
	}

	hashedRefreshToken, err := bcrypt.GenerateFromPassword(refreshToken, bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = database.DB.Exec(
		"INSERT INTO refresh_tokens (user_id, token_hash, ip_address, user_agent) VALUES ($1, $2, $3, $4)",
		userID, hashedRefreshToken, ipAddress, userAgent,
	)

	if err != nil {
		log.Println("Ошибка добавления RefreshToken в БД:", err)
		return err
	}

	return nil
}

func GetTokenHashAndIPAddress(userID string) (string, string, error) {
	var tokenHash string
	var ipAddress string

	err := database.DB.QueryRow("SELECT token_hash, ip_address FROM refresh_tokens WHERE user_id = $1", userID).Scan(&tokenHash, &ipAddress)
	if err != nil {
		return "", "", err
	}

	return tokenHash, ipAddress, nil
}

func TerminateOtherSessions(userID string, refreshTokenBytes []byte) error {
	rows, err := database.DB.Query("SELECT token_hash FROM refresh_tokens WHERE user_id = $1", userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var hashedToken string
	var matchedTokenHash string

	for rows.Next() {
		if err := rows.Scan(&hashedToken); err != nil {
			return err
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedToken), refreshTokenBytes)
		if err == nil {
			matchedTokenHash = hashedToken
		}
	}

	if matchedTokenHash == "" {
		return fmt.Errorf("Не найден refresh токен")
	}

	_, err = database.DB.Exec("DELETE FROM refresh_tokens WHERE user_id = $1 AND token_hash != $2", userID, matchedTokenHash)
	return err
}
