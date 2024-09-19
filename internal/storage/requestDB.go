package storage

import (
	storage "auth-service/internal/database"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func StoreRefreshTokenInDB(userID string, refreshToken []byte, ipAddress string) error {
	hashedRefreshToken, err := bcrypt.GenerateFromPassword(refreshToken, bcrypt.DefaultCost)
    if err != nil {
        return err
    }
    
    _, err = storage.DB.Exec(
        "INSERT INTO refresh_tokens (user_id, token_hash, ip_address) VALUES ($1, $2, $3)",
        userID, hashedRefreshToken, ipAddress,
    )

    if err != nil {
        log.Println("Ошибка добавления RefreshToken в БД:", err)
        return err
    }

    return nil
}

func GetTokenHashAndIPAddress(userID string) (string, string, error) {
	var token_hash string
	var ip_address string

	err := storage.DB.QueryRow("SELECT token_hash, ip_address FROM refresh_tokens WHERE user_id = $1", userID).Scan(&token_hash, &ip_address)
	if err != nil {
		return "", "", err
	}

	return token_hash, ip_address, nil
}

func InvalidateRefreshTokenInDB(userID, hashedToken string) error {
	_, err := storage.DB.Exec("DELETE FROM refresh_tokens WHERE user_id = $1 AND token_hash = $2", userID, hashedToken)
	if err != nil {
		return err
	}

	return nil
}