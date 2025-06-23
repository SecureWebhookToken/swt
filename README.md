# SecureWebhookToken (SWT)

![GitHub Tag](https://img.shields.io/github/v/tag/SecureWebhookToken/swt?label=Version)
[![Go Report Card](https://goreportcard.com/badge/github.com/SecureWebhookToken/swt)](https://goreportcard.com/report/github.com/SecureWebhookToken/swt)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/SecureWebhookToken/swt?style=flat)
![Coverage](assets/coverage-badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/SecureWebhookToken/swt)](https://pkg.go.dev/github.com/SecureWebhookToken/swt)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

SecureWebhookToken is an [Internet-Draft](https://datatracker.ietf.org/doc/draft-knauer-secure-webhook-token/)
for sending secure Webhooks, based on the [JWT](https://datatracker.ietf.org/doc/html/rfc7519) standard.
See [Documentation](https://securewebhooktoken.github.io) for more details.

# Install
`go get github.com/SecureWebhookToken/swt`

# Examples

## Client / Server

```go
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
		return nil
	}, nil))

	slog.Error("Server error", "error", http.ListenAndServe(":8080", nil))
}
```