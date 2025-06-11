package swt_test

import (
	"testing"
	"time"

	"github.com/SecureWebhookToken/swt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func generateClaims(issuer string) *swt.WebhookClaims {
	return &swt.WebhookClaims{
		Webhook: swt.Webhook{
			Event: "user.create",
			Data:  nil,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  nil,
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}
}

func TestWithID(t *testing.T) {
	uuidStr := uuid.NewString()
	tests := []struct {
		name    string
		swt     *swt.SecureWebhookToken
		want    string
		wantErr error
	}{
		{
			name:    "Set an empty id",
			swt:     swt.NewWithClaims(generateClaims("securewebhooktoken.github.io"), swt.WithID("")),
			want:    "",
			wantErr: jwt.ErrTokenInvalidId,
		},
		{
			name: "Set a valid uuid",
			swt:  swt.NewWithClaims(generateClaims("securewebhooktoken.github.io"), swt.WithID(uuidStr)),
			want: uuidStr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := tt.swt.SignedString(secretKey)
			if tt.wantErr != nil {
				assert.ErrorContains(t, gotErr, tt.wantErr.Error())
			}
			assert.Equal(t, tt.want, tt.swt.ID())
		})
	}
}

func TestWithSubject(t *testing.T) {
	tests := []struct {
		name string
		swt  *swt.SecureWebhookToken
		want string
	}{
		{
			name: "Set an empty subject",
			swt:  swt.NewWithClaims(generateClaims("securewebhooktoken.github.io"), swt.WithSubject("")),
			want: "",
		},
		{
			name: "Set a non-empty subject",
			swt:  swt.NewWithClaims(generateClaims("securewebhooktoken.github.io"), swt.WithSubject("12349393828")),
			want: "12349393828",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, _ := tt.swt.Claims().GetSubject()
			assert.Equal(t, tt.want, sub)
		})
	}
}

func TestWithIssuer(t *testing.T) {
	tests := []struct {
		name    string
		swt     *swt.SecureWebhookToken
		want    string
		wantErr error
	}{
		{
			name:    "Set an empty issuer",
			swt:     swt.NewWithClaims(generateClaims("")),
			want:    "",
			wantErr: jwt.ErrTokenInvalidIssuer,
		},
		{
			name: "Set a not empty issuer",
			swt:  swt.NewWithClaims(generateClaims(issuer)),
			want: issuer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := tt.swt.SignedString(secretKey)
			if tt.wantErr != nil {
				//t.Log(tt.wantErr.Error())
				assert.ErrorContains(t, gotErr, tt.wantErr.Error())
			}
			iss, _ := tt.swt.Claims().GetIssuer()
			assert.Equal(t, tt.want, iss)
		})
	}
}

func TestWithAudience(t *testing.T) {
	tests := []struct {
		name    string
		swt     *swt.SecureWebhookToken
		want    jwt.ClaimStrings
		wantErr error
	}{
		{
			name: "Set no audience claim and expect the default case",
			swt:  swt.NewWithClaims(generateClaims(issuer)),
			want: nil,
		},
		{
			name: "Set an empty audience",
			swt:  swt.NewWithClaims(generateClaims(issuer), swt.WithAudience()),
			want: nil,
		},
		{
			name: "Set one recipient as an audience claim",
			swt:  swt.NewWithClaims(generateClaims(issuer), swt.WithAudience("me")),
			want: jwt.ClaimStrings{"me"},
		},
		{
			name: "Set multiple recipients as an audience claim",
			swt:  swt.NewWithClaims(generateClaims(issuer), swt.WithAudience("me", "him", "her")),
			want: jwt.ClaimStrings{"me", "him", "her"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := tt.swt.SignedString(secretKey)
			if tt.wantErr != nil {
				assert.ErrorContains(t, gotErr, tt.wantErr.Error())
			}
			aud, _ := tt.swt.Claims().GetAudience()
			assert.Equal(t, tt.want, aud)
		})
	}
}

func TestWithExpiresAt(t *testing.T) {
	want := jwt.NewNumericDate(now)
	got := swt.NewWithClaims(generateClaims(issuer), swt.WithExpiresAt(now))
	exp, _ := got.Claims().GetExpirationTime()
	assert.Equal(t, want, exp)
}

func TestWithNotBefore(t *testing.T) {
	want := jwt.NewNumericDate(now)
	got := swt.NewWithClaims(generateClaims(issuer), swt.WithNotBefore(now))
	nbf, _ := got.Claims().GetNotBefore()
	assert.Equal(t, want, nbf)
}

func TestWithSigningMethod(t *testing.T) {
	tests := []struct {
		name    string
		swt     *swt.SecureWebhookToken
		want    string
		wantErr error
	}{
		{
			name:    "Set no signing method and expect default one",
			swt:     swt.NewWithClaims(generateClaims(issuer)),
			want:    jwt.SigningMethodHS256.Alg(),
			wantErr: nil,
		},
		{
			name:    "Set signing method: HS256",
			swt:     swt.NewWithClaims(generateClaims(issuer), swt.WithSigningMethod(jwt.SigningMethodHS256)),
			want:    jwt.SigningMethodHS256.Alg(),
			wantErr: nil,
		},
		{
			name:    "Set signing method: HS384",
			swt:     swt.NewWithClaims(generateClaims(issuer), swt.WithSigningMethod(jwt.SigningMethodHS384)),
			want:    jwt.SigningMethodHS384.Alg(),
			wantErr: nil,
		},
		{
			name:    "Set signing method: HS512",
			swt:     swt.NewWithClaims(generateClaims(issuer), swt.WithSigningMethod(jwt.SigningMethodHS512)),
			want:    jwt.SigningMethodHS512.Alg(),
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.swt.Algorithm())
		})
	}
}
