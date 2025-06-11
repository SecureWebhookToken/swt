package main

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/SecureWebhookToken/swt"
)

const (
	issuer = "https://example.com"
	url    = "http://localhost:8080/webhook"
)

var secretKey = []byte("test")

func main() {
	go startServer()

	req, err := swt.BuildRequest(url, "issuer", "send.stars", []byte(`{"username": "me", "stars": "567"}`), secretKey)
	if err != nil {
		slog.Error(fmt.Errorf("error building request: %w", err).Error())
		return
	}

	httpClient := &http.Client{}
	res, err := httpClient.Do(req)
	if err != nil {
		slog.Error("Error executing request", "error", err)
		return
	}
	slog.Info("Successfully executed request", "status", res.StatusCode)
}

func startServer() {
	http.Handle("/webhook", swt.NewHandlerFunc(secretKey, func(token *swt.SecureWebhookToken) error {
		slog.Info("Successfully received token: " + token.String())

		//Validate issuer
		if token.Issuer() != issuer {
			return fmt.Errorf("invalid issuer")
		}

		return nil
	}, nil))

	slog.Error("Server error", "error", http.ListenAndServe(":8080", nil))
}
