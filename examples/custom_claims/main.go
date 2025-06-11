package main

import (
	"fmt"
	"github.com/SecureWebhookToken/swt"
	"github.com/golang-jwt/jwt/v5"
	"log/slog"
	"time"
)

var secretKey = []byte("topSecret")

type CustomClaims struct {
	Foo string `json:"foo"`
	swt.WebhookClaims
}

func main() {
	cc := &CustomClaims{
		Foo: "bar",
		WebhookClaims: swt.NewWebhookClaims(
			"me",
			"foo-bar.test",
			map[string]interface{}{"foo": "bar", "bar": "baz"},
		),
	}

	token := swt.NewWithClaims(cc,
		swt.WithSubject("testing"),
		swt.WithExpiresAt(time.Now().Add(15*time.Minute)),
	)

	tokenStr, err := token.SignedString(secretKey)
	if err != nil {
		slog.Error("token creation failed", "error", err)
		return
	}

	analyseToken(tokenStr, &CustomClaims{})
}

func analyseToken(tokenStr string, claims swt.Claims) {
	if claims == nil {
		claims = &swt.WebhookClaims{}
	}

	p := jwt.NewParser()
	t, parts, err := p.ParseUnverified(tokenStr, claims)
	if err != nil {
		slog.Error("parsing token failed", "error", err)
		return
	}

	slog.Info(fmt.Sprintf("Token string: %s", tokenStr))
	slog.Info(fmt.Sprintf("Claims: %#v", t.Claims))

	for i := 0; i < len(parts)-1; i++ {
		data, err := p.DecodeSegment(parts[i])
		if err != nil {
			slog.Error("decoding segment failed", "error", err)
		}
		if i == 0 {
			slog.Info(fmt.Sprintf(" Header: %s", data))
		}

		if i == 1 {
			slog.Info(fmt.Sprintf("Payload: %s", data))
		}
	}

	token, err := swt.Parse(tokenStr, secretKey)
	if err != nil {
		slog.Error("swt parsing failed", "error", err)
		return
	}

	slog.Info(fmt.Sprintf("\nToken:\n%s", token))
}
