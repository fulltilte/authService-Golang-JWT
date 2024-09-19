package auth

import (
	str "auth-service/internal/storage"
	pkg "auth-service/pkg"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/go-chi/chi/v5"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
    SecretKey string `env:"SECRET_KEY"`
}

var JwtKey []byte

var cfg Config

func init() {
    if err := env.Parse(&cfg); err != nil {
        log.Fatalf("Ошибка загрузки ENV: %s", err)
    }
    JwtKey = []byte(cfg.SecretKey)
}	

type TokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IPAddress    string `json:"ip_address"`
}

func GenerateTokenPair(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	ipAddress := r.RemoteAddr

	accessTokenString, err := GenerateAccessToken(userID, ipAddress)
	if err != nil {
		http.Error(w, "Ошибка создания AccessToken", http.StatusInternalServerError)
		return
	}

	refreshTokenString, err := GenerateRefreshToken(userID, ipAddress)
	if err != nil {
		http.Error(w, "Ошибка создания RefreshToken", http.StatusInternalServerError)
		return
	}

	response := TokenData{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		IPAddress:    ipAddress,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.RemoteAddr
	userID := chi.URLParam(r, "user_id")
    refreshToken := chi.URLParam(r, "refresh_token")

	tokenBytes, err := base64.URLEncoding.DecodeString(refreshToken)
	if err != nil {
		http.Error(w, "Некорректный Refresh токен", http.StatusBadRequest)
		return
	}

    tokenHash, storedIpAddress, err := str.GetTokenHashAndIPAddress(userID)
    if err != nil {
        http.Error(w, "Ошибка получения токена из базы данных", http.StatusInternalServerError)
        return
    }

	err = bcrypt.CompareHashAndPassword([]byte(tokenHash), tokenBytes)
	if err != nil {
		http.Error(w, "Refresh токен недействителен", http.StatusUnauthorized)
		return
	}

    if ipAddress != storedIpAddress {
        pkg.SendEmailWarning(userID)
    }

    err = str.InvalidateRefreshTokenInDB(userID, tokenHash)
    if err != nil {
        http.Error(w, "Ошибка инвалидизации токена", http.StatusInternalServerError)
        return
    }

    newAccessToken, err := GenerateAccessToken(userID, ipAddress)
    if err != nil {
        http.Error(w, "Ошибка создания AccessToken", http.StatusInternalServerError)
        return
    }

    newRefreshToken, err := GenerateRefreshToken(userID, ipAddress)
    if err != nil {
        http.Error(w, "Ошибка создания RefreshToken", http.StatusInternalServerError)
        return
    }

    response := TokenData{
        AccessToken:  newAccessToken,
        RefreshToken: newRefreshToken,
        IPAddress:    ipAddress,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func GenerateAccessToken(userID, ipAddress string) (string, error) {
	expTimeAccessToken := time.Now().Add(60 * time.Minute).Unix()

	token := jwt.New(jwt.SigningMethodHS512)
	token.Header["kid"] = "auth"

	claims := token.Claims.(jwt.MapClaims)
	claims["ipAddress"] = ipAddress
	claims["exp"] = expTimeAccessToken
	claims["sub"] = userID

	tokenString, err := token.SignedString(JwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func GenerateRefreshToken(userID, ipAddress string) (string, error) {
    refreshToken := make([]byte, 32)
    rand.Read(refreshToken)

    err := str.StoreRefreshTokenInDB(userID, refreshToken, ipAddress)
    if err != nil {
        return "", err
    }

    return base64.URLEncoding.EncodeToString(refreshToken), nil
}