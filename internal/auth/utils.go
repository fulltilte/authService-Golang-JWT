package auth

import (
	"net/http"
)

func handleError(w http.ResponseWriter, errMsg string, statusCode int) {
	http.Error(w, errMsg, statusCode)
}
