package pkg

import (
	"log"
)

func SendEmailWarning(userID string) {
	log.Printf("Отправка сообщения пользователю (%s) об изменении IpAddress\n", userID)
}