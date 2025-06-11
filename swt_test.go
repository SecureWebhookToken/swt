package swt_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SecureWebhookToken/swt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var (
	secretKey = []byte("topSecret")
	now       = time.Now()
)

const (
	issuer = "securewebhooktoken.github.io"
)

func init() {
	// Disable default logging with slog
	//slog.SetDefault(slog.New(slogscope.NewNilHandler()))
}

func TestNew(t *testing.T) {
	tests := []struct {
		name  string
		event string
		data  any
		want  swt.Webhook
	}{
		{
			"Create new SecureWebhookToken with data",
			"user.create",
			map[string]string{
				"firstname": "mister",
				"lastname":  "x",
			},
			swt.Webhook{
				Event: "user.create",
				Data: map[string]string{
					"firstname": "mister",
					"lastname":  "x",
				},
			},
		},
		{
			"Create new SecureWebhookToken with empty event",
			"",
			map[string]string{
				"firstname": "mister",
				"lastname":  "x",
			},
			swt.Webhook{
				Event: "",
				Data: map[string]string{
					"firstname": "mister",
					"lastname":  "x",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := swt.New(issuer, tt.event, tt.data)
			assert.Equal(t, tt.want, got.Webhook())
		})
	}
}

func TestNewWithClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims swt.Claims
		want   *swt.SecureWebhookToken
		panics bool
	}{
		{
			name:   "Create new SecureWebhookToken without claims",
			claims: nil,
			panics: true,
		},
		{
			name: "Create new SecureWebhookToken with claims",
			claims: &swt.WebhookClaims{
				Webhook: swt.Webhook{},
				RegisteredClaims: jwt.RegisteredClaims{
					ID: "test",
				},
			},
			want: swt.NewWithClaims(&swt.WebhookClaims{
				Webhook: swt.Webhook{},
				RegisteredClaims: jwt.RegisteredClaims{
					ID: "test",
				},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.panics {
				assert.Panics(t, func() {
					swt.NewWithClaims(tt.claims)
				})
			} else {
				got := swt.NewWithClaims(tt.claims)
				assert.Equal(t, got.Claims(), tt.want.Claims())
			}
		})
	}
}

func TestSecureWebhookToken_SignedString(t *testing.T) {
	signingKey := []byte("test")
	tests := []struct {
		name    string
		swt     *swt.SecureWebhookToken
		want    bool
		wantErr error
	}{
		{
			name: "Valid token",
			swt: swt.New(
				issuer,
				"user.create",
				map[string]string{
					"firstname": "mister",
					"lastname":  "x",
				},
			),
			want:    true,
			wantErr: nil,
		},
		{
			name: "Invalid token: with missing issuer",
			swt: swt.New(
				"",
				"user.create",
				map[string]string{
					"firstname": "mister",
					"lastname":  "x",
				},
			),
			want:    false,
			wantErr: jwt.ErrTokenInvalidIssuer,
		},
		{
			name: "Invalid token: with missing event",
			swt: swt.New(
				issuer,
				"",
				map[string]string{
					"firstname": "mister",
					"lastname":  "x",
				},
			),
			want:    false,
			wantErr: jwt.ErrTokenInvalidClaims,
		},
		//{
		//	name:    "Invalid token: not created with New method",
		//	swt:     &swt.SecureWebhookToken{},
		//	want:    false,
		//	wantErr: swt.ErrTokenInvalid,
		//},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.swt.SignedString(signingKey)
			if err == nil {
				assert.NotEmpty(t, got)
			}
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestSecureWebhookToken_Validate(t *testing.T) {
	tests := []struct {
		name    string
		swt     *swt.SecureWebhookToken
		wantErr error
	}{
		{
			name:    "Validation successful",
			swt:     swt.New(issuer, "user.create", nil),
			wantErr: nil,
		},
		{
			name:    "Validation failed: missing event",
			swt:     swt.New(issuer, "", nil),
			wantErr: jwt.ErrTokenInvalidClaims,
		},
		{
			name:    "Verification failed: invalid issuer",
			swt:     swt.New("", "user.create", nil),
			wantErr: jwt.ErrTokenInvalidIssuer,
		},
		{
			name: "Validation failed: missing exp",
			swt: swt.NewWithClaims(&swt.WebhookClaims{
				Webhook: swt.Webhook{Event: "test"},
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "me",
					Subject:   "",
					Audience:  nil,
					ExpiresAt: nil,
					NotBefore: jwt.NewNumericDate(time.Now()),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ID:        "1",
				}}),
			wantErr: jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name: "Validation failed: missing nbf",
			swt: swt.NewWithClaims(&swt.WebhookClaims{
				Webhook: swt.Webhook{Event: "test"},
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "me",
					Subject:   "",
					Audience:  nil,
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
					NotBefore: nil,
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ID:        "1",
				}}),
			wantErr: jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name: "Validation failed: invalid subject",
			swt: swt.NewWithClaims(&swt.WebhookClaims{
				Webhook: swt.Webhook{Event: "test"},
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    issuer,
					Subject:   "wrong_subject",
					Audience:  nil,
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					NotBefore: jwt.NewNumericDate(now),
					IssuedAt:  jwt.NewNumericDate(now),
					ID:        uuid.NewString(),
				},
			}),
			wantErr: nil,
		},
		{
			name: "Validation failed: invalid id",
			swt: swt.NewWithClaims(&swt.WebhookClaims{
				Webhook: swt.Webhook{Event: "send.test"},
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        "",
					Issuer:    issuer,
					Audience:  nil,
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					NotBefore: jwt.NewNumericDate(now),
					IssuedAt:  jwt.NewNumericDate(now),
				},
			}),
			wantErr: jwt.ErrTokenInvalidId,
		},
		{
			name: "Validation failed: missing iat",
			swt: swt.NewWithClaims(&swt.WebhookClaims{
				Webhook: swt.Webhook{Event: "send.test"},
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        "WRONG_UUID",
					Issuer:    issuer,
					Audience:  nil,
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					NotBefore: jwt.NewNumericDate(now),
					IssuedAt:  nil,
				},
			}),
			wantErr: fmt.Errorf("%w: iat", jwt.ErrTokenRequiredClaimMissing),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.swt.Validate()
			if tt.wantErr == nil {
				assert.Nil(t, got)
			} else {
				assert.ErrorContains(t, got, tt.wantErr.Error())
			}
		})
	}
}

func TestParse(t *testing.T) {
	validToken := swt.New(issuer, "user.create", nil)
	validTokenStr, _ := validToken.SignedString(secretKey)

	invalidToken := swt.New(issuer, "user.create", nil)
	invalidTokenStr, _ := invalidToken.SignedString([]byte("different_key"))

	jwtTokenStr, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Issuer: "me", IssuedAt: jwt.NewNumericDate(time.Now()), NotBefore: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(secretKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		tokenStr string
		want     *swt.SecureWebhookToken
		wantErr  error
	}{
		{
			name:     "Valid token",
			tokenStr: validTokenStr,
		},
		{
			name:     "Invalid token: invalid signature",
			tokenStr: invalidTokenStr,
			wantErr:  jwt.ErrSignatureInvalid,
		},
		{
			name:     "Invalid token: not a SecureWebhookToken",
			tokenStr: jwtTokenStr,
			wantErr:  jwt.ErrTokenInvalidClaims,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := swt.Parse(tt.tokenStr, secretKey)
			if err == nil {
				assert.Equal(t, true, got.Valid())
			} else {
				assert.Nil(t, got)
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestNewHandlerFuncWithHEADRequest(t *testing.T) {
	data := map[string]any{"cool": 123.0, "data": "test"}
	token := swt.New(issuer, "send.nothing", data)
	tokenStr, err := token.SignedString(secretKey)
	assert.Nil(t, err)

	handleFn := func(token *swt.SecureWebhookToken) error {
		assert.Equal(t, "send.nothing", token.Webhook().Event)
		assert.Equal(t, data, token.Webhook().Data)
		return nil
	}

	handler := swt.NewHandlerFunc(secretKey, handleFn, nil)

	t.Run("Successful webhook request via HEAD method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "http://example.com", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr))

		w := httptest.NewRecorder()
		handler(w, req)

		res := w.Result()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		assert.Empty(t, string(body))
		assert.Equal(t, http.StatusNoContent, res.StatusCode)
	})

	t.Run("Wrong method webhook request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr))

		w := httptest.NewRecorder()
		handler(w, req)

		res := w.Result()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		assert.Empty(t, string(body))
		assert.Equal(t, http.StatusMethodNotAllowed, res.StatusCode)
	})

	t.Run("Invalid authorization header webhook request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "http://example.com", nil)
		req.Header.Set("Authorization", tokenStr)

		w := httptest.NewRecorder()
		handler(w, req)

		res := w.Result()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		assert.Empty(t, string(body))
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("Parse error due to invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "http://example.com", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr+"fjasdfhkjasf"))

		w := httptest.NewRecorder()
		handler(w, req)

		res := w.Result()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		assert.Empty(t, string(body))
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}

func TestNewHandlerFuncWithPOSTRequest(t *testing.T) {
	tests := []struct {
		name               string
		requestType        string
		hash               string
		hashAlg            string
		size               int64
		data               []byte
		expectedHTTPStatus int
		handlerOpts        *swt.HandlerOptions
	}{
		{
			name:               "empty body",
			requestType:        http.MethodPost,
			hash:               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			data:               []byte{},
			hashAlg:            "SHA-256",
			expectedHTTPStatus: http.StatusNoContent,
		},
		{
			name:               "not empty body",
			requestType:        http.MethodPost,
			hash:               "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			data:               []byte("test"),
			size:               4,
			hashAlg:            "SHA-256",
			expectedHTTPStatus: http.StatusNoContent,
		},
		{
			name:               "not empty body, but wrong body size",
			requestType:        http.MethodPost,
			hash:               "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			data:               []byte("test"),
			size:               10,
			hashAlg:            "SHA-256",
			expectedHTTPStatus: http.StatusBadRequest,
		},
		{
			name:               "default content hash algorithm should be SHA3-256",
			requestType:        http.MethodPost,
			hash:               "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80",
			data:               []byte("test"),
			size:               4,
			hashAlg:            "",
			expectedHTTPStatus: http.StatusNoContent,
		},
		{
			name:               "unsupported content hash algorithm SHA-224",
			requestType:        http.MethodPost,
			data:               []byte("test"),
			size:               4,
			hashAlg:            "SHA-224",
			expectedHTTPStatus: http.StatusBadRequest,
		},
		{
			name:               "valid SHA-256 hash",
			requestType:        http.MethodPost,
			hash:               "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			data:               []byte("test"),
			size:               4,
			hashAlg:            "SHA-256",
			expectedHTTPStatus: http.StatusNoContent,
		},
		{
			name:               "valid SHA-384 hash",
			requestType:        http.MethodPost,
			hash:               "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9",
			data:               []byte("test"),
			size:               4,
			hashAlg:            "SHA-384",
			expectedHTTPStatus: http.StatusNoContent,
		},
		{
			name:               "valid SHA-512 hash",
			requestType:        http.MethodPost,
			hash:               "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
			data:               []byte("test"),
			size:               4,
			hashAlg:            "SHA-512",
			expectedHTTPStatus: http.StatusNoContent,
		},
		{
			name:               "valid SHA3-256 hash",
			requestType:        http.MethodPost,
			hash:               "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80",
			data:               []byte("test"),
			size:               4,
			hashAlg:            "SHA3-256",
			expectedHTTPStatus: http.StatusNoContent,
		},
		{
			name:               "valid SHA3-384 hash",
			requestType:        http.MethodPost,
			hash:               "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd",
			data:               []byte("test"),
			size:               4,
			hashAlg:            "SHA3-384",
			expectedHTTPStatus: http.StatusNoContent,
		},
		{
			name:               "valid SHA3-512 hash",
			requestType:        http.MethodPost,
			hash:               "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14",
			data:               []byte("test"),
			size:               4,
			hashAlg:            "SHA3-512",
			expectedHTTPStatus: http.StatusNoContent,
		},
		{
			name:               "invalid content hash",
			requestType:        http.MethodPost,
			data:               []byte("test"),
			size:               4,
			hashAlg:            "SHA-384",
			expectedHTTPStatus: http.StatusBadRequest,
		},
		{
			name:               "max body size reached",
			requestType:        http.MethodPost,
			hash:               "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80",
			data:               []byte("test"),
			size:               4,
			hashAlg:            "SHA3-256",
			handlerOpts:        &swt.HandlerOptions{MaxBodySize: 3},
			expectedHTTPStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			whData := map[string]any{"hash": tt.hash, "size": tt.size, "hashAlg": tt.hashAlg}
			token := swt.New(issuer, "send.nothing", whData)
			tokenStr, err := token.SignedString(secretKey)
			assert.Nil(t, err)

			handleFn := func(token *swt.SecureWebhookToken) error {
				assert.Equal(t, "send.nothing", token.Webhook().Event)
				assert.Equal(t, tt.data, token.Webhook().Data)
				return nil
			}

			handler := swt.NewHandlerFunc(secretKey, handleFn, tt.handlerOpts)

			buf := bytes.NewBuffer(tt.data)

			req := httptest.NewRequest(http.MethodPost, "http://example.com", buf)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr))

			w := httptest.NewRecorder()
			handler(w, req)

			res := w.Result()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			assert.Empty(t, string(body))
			assert.Equal(t, tt.expectedHTTPStatus, res.StatusCode)
		})
	}
}
