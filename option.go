package swt

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type Option func(swt *SecureWebhookToken)

// WithSubject overrides the default sub claim.
func WithSubject(s string) Option {
	return func(swt *SecureWebhookToken) {
		swt.Claims().wc().Subject = s
	}
}

// WithExpiresAt overrides the default exp claim.
func WithExpiresAt(t time.Time) Option {
	return func(swt *SecureWebhookToken) {
		swt.Claims().wc().ExpiresAt = jwt.NewNumericDate(t)
	}
}

// WithNotBefore overrides the default nbf claim.
func WithNotBefore(t time.Time) Option {
	return func(swt *SecureWebhookToken) {
		swt.Claims().wc().NotBefore = jwt.NewNumericDate(t)
	}
}

// WithID overrides the jti claim to the given id which must be a valid UUID to be verified as SecureWebhookToken.
func WithID(id string) Option {
	return func(swt *SecureWebhookToken) {
		swt.Claims().wc().ID = id
	}
}

// WithAudience overrides the aud claim.
// The Audience claim is optional and is nil by default.
// It can consist of zero or more recipients containing a StringOrURI value.
func WithAudience(ids ...string) Option {
	return func(swt *SecureWebhookToken) {
		swt.Claims().wc().Audience = ids
	}
}

// WithSigningMethod allows overriding the default signing method HS256.
// For the convenience of SecureHookTokens usage, only symmetrical signatures are supported. (HS256, HS384 and HS512)
func WithSigningMethod(method *jwt.SigningMethodHMAC) Option {
	return func(swt *SecureWebhookToken) {
		swt.token.Method = method
	}
}
