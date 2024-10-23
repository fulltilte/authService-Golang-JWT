package auth

import (
	"auth-service/pkg"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"

	"auth-service/internal/storage"
	"github.com/golang-jwt/jwt/v5"
)

type TokenData struct {
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IPAddress    string `json:"ip_address"`
}

func GenerateTokenPair(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Printf("(GenerateTokenPair) Ошибка декодирования JSON: %v", err)
		handleError(w, "Ошибка декодирования JSON", http.StatusBadRequest)
		return
	}

	user, err := storage.GetUserByEmail(input.Email)
	if err != nil || !CheckPassword(input.Password, user.Password) {
		log.Printf("(GenerateTokenPair) Неверные учетные данные для пользователя %s", input.Email)
		handleError(w, "Неверные учетные данные", http.StatusUnauthorized)
		return
	}

	ipAddress := r.RemoteAddr
	userAgent := r.Header.Get("User-Agent")

	tokenData, err := GenerateTokenData(user.ID, userAgent, ipAddress)
	if err != nil {
		log.Printf("(GenerateTokenPair) Ошибка генерации токенов для пользователя %s: %v", user.ID, err)
		handleError(w, "Ошибка генерации токенов", http.StatusInternalServerError)
		return
	}

	setTokenCookies(w, tokenData)
	log.Printf("Успешная генерация токенов для пользователя %s", user.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenData)
}

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.RemoteAddr

	_, refreshToken, userID, err := GetTokensFromCookie(r)
	if err != nil {
		log.Printf("(RefreshTokenHandler) Ошибка получения токенов из cookie: %v", err)
		handleError(w, "Ошибка получения токенов из cookie", http.StatusInternalServerError)
		return
	}

	refreshTokenBytes, err := base64.URLEncoding.DecodeString(refreshToken)
	if err != nil {
		log.Printf("(RefreshTokenHandler) Неверный формат refresh токена: %v", err)
		handleError(w, "Неверный формат refresh токена", http.StatusUnauthorized)
		return
	}

	tokenHash, storedIpAddress, err := storage.GetTokenHashAndIPAddress(userID)
	if err != nil {
		log.Printf("(RefreshTokenHandler) Токен не найден для пользователя %s: %v", userID, err)
		handleError(w, "Токен не найден", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(tokenHash), refreshTokenBytes)
	if err != nil {
		log.Printf("(RefreshTokenHandler) Неверный refresh токен для пользователя %s", userID)
		handleError(w, "Неверный refresh токен", http.StatusUnauthorized)
		return
	}

	userAgent := r.Header.Get("User-Agent")
	newAccessToken, err := GenerateAccessToken(userID, userAgent, ipAddress)
	if err != nil {
		log.Printf("(RefreshTokenHandler) Ошибка генерации нового access токена для пользователя %s: %v", userID, err)
		handleError(w, "Ошибка генерации нового access токена", http.StatusInternalServerError)
		return
	}

	if ipAddress != storedIpAddress {
		log.Printf("IP-адрес изменен для пользователя %s. Отправляем предупреждение.", userID)
		pkg.SendEmailWarning(userID)
	}

	log.Printf("Токен успешно обновлен для пользователя %s", userID)

	response := TokenData{
		AccessToken: newAccessToken,
		IPAddress:   r.RemoteAddr,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func LogoutOtherSessions(w http.ResponseWriter, r *http.Request) {
	_, refreshToken, userID, err := GetTokensFromCookie(r)
	if err != nil {
		log.Printf("(LogoutOtherSessions) Ошибка получения токенов из cookie: %v", err)
		handleError(w, "Ошибка получения токенов из cookie", http.StatusInternalServerError)
		return
	}

	refreshTokenBytes, err := base64.URLEncoding.DecodeString(refreshToken)
	if err != nil {
		log.Printf("(LogoutOtherSessions) Неверный формат refresh токена для пользователя %s: %v", userID, err)
		handleError(w, "Неверный формат refresh токена", http.StatusUnauthorized)
		return
	}

	err = storage.TerminateOtherSessions(userID, refreshTokenBytes)
	if err != nil {
		log.Printf("(LogoutOtherSessions) Ошибка завершения других сессий для пользователя %s: %v", userID, err)
		handleError(w, "Ошибка завершения других сессий", http.StatusInternalServerError)
		return
	}

	log.Printf("Другие сессии успешно завершены для пользователя %s", userID)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Other sessions terminated"))
}

func GenerateTokenData(userID, userAgent, ipAddress string) (TokenData, error) {
	accessToken, err := GenerateAccessToken(userID, userAgent, ipAddress)
	if err != nil {
		log.Printf("(GenerateTokenData) Ошибка генерации access токена для пользователя %s: %v", userID, err)
		return TokenData{}, err
	}

	refreshToken, err := GenerateRefreshToken(userID, userAgent, ipAddress)
	if err != nil {
		log.Printf("(GenerateTokenData) Ошибка генерации refresh токена для пользователя %s: %v", userID, err)
		return TokenData{}, err
	}

	log.Printf("Токены успешно сгенерированы для пользователя %s", userID)

	return TokenData{
		UserID:       userID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IPAddress:    ipAddress,
	}, nil
}

func setTokenCookies(w http.ResponseWriter, tokenData TokenData) {
	userIDCookie := &http.Cookie{
		Name:     "user_id",
		Value:    tokenData.UserID,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
	}

	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    tokenData.AccessToken,
		Expires:  time.Now().Add(60 * time.Minute),
		HttpOnly: true,
		Secure:   true,
	}

	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    tokenData.RefreshToken,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
	}

	http.SetCookie(w, userIDCookie)
	http.SetCookie(w, accessCookie)
	http.SetCookie(w, refreshCookie)

	log.Printf("Куки с токенами успешно установлены для пользователя %s", tokenData.UserID)
}

func GenerateAccessToken(userID, userAgent, ipAddress string) (string, error) {
	expTime := time.Now().Add(60 * time.Minute).Unix()
	token := jwt.New(jwt.SigningMethodHS512)

	claims := token.Claims.(jwt.MapClaims)
	claims["userAgent"] = userAgent
	claims["userID"] = userID
	claims["ipAddress"] = ipAddress
	claims["exp"] = expTime

	log.Printf("Access токен сгенерирован для пользователя %s", userID)
	return token.SignedString(JwtKey)
}

func GenerateRefreshToken(userID, userAgent, ipAddress string) (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		log.Printf("(GenerateRefreshToken) Ошибка генерации refresh токена для пользователя %s: %v", userID, err)
		return "", err
	}

	err = storage.StoreRefreshTokenInDB(token, userID, userAgent, ipAddress)
	if err != nil {
		log.Printf("(GenerateRefreshToken) Ошибка сохранения refresh токена в базе для пользователя %s: %v", userID, err)
		return "", err
	}

	log.Printf("Refresh токен сгенерирован и сохранен для пользователя %s", userID)
	return base64.URLEncoding.EncodeToString(token), nil
}

func GetTokensFromCookie(r *http.Request) (string, string, string, error) {
	refreshCookie, err := r.Cookie("refresh_token")
	if err != nil {
		log.Printf("(GetTokensFromCookie) Refresh токен не найден в cookie: %v", err)
		return "", "", "", fmt.Errorf("no refresh token found in cookies")
	}

	accessCookie, err := r.Cookie("access_token")
	if err != nil {
		log.Printf("(GetTokensFromCookie) Access токен не найден в cookie: %v", err)
		return "", "", "", fmt.Errorf("no access token found in cookies")
	}

	userIDCookie, err := r.Cookie("user_id")
	if err != nil {
		log.Printf("(GetTokensFromCookie) user_id не найден в cookie: %v", err)
		return "", "", "", fmt.Errorf("no user_id found in cookies")
	}

	log.Printf("Токены успешно получены из cookie для пользователя %s", userIDCookie.Value)
	return accessCookie.Value, refreshCookie.Value, userIDCookie.Value, nil
}
