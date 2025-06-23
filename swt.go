package swt

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	defaultExpiration    = 5 * time.Minute
	defaultHashAlgorithm = "SHA3-256"
	defaultMaxBodySize   = 32 << 20 // 32MB
	webhookClaim         = "webhook"

	HeadMaxDataSize = 6 << 10
	// Supported hash algorithms
	SHA256   = "SHA-256"
	SHA384   = "SHA-384"
	SHA512   = "SHA-512"
	SHA3_256 = "SHA3-256"
	SHA3_384 = "SHA3-384"
	SHA3_512 = "SHA3-512"
)

var (
	ErrInvalidToken             = errors.New("invalid token - please use New or NewWithClaims to properly initialize token")
	ErrMissingClaims            = errors.New("missing claims")
	ErrInvalidOption            = errors.New("invalid option")
	ErrInvalidJSON              = errors.New("invalid json data")
	ErrInvalidData              = errors.New("invalid data")
	ErrUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")

	// validSigningMethods defines the allowed symmetrical HMAC-SHA signing methods.
	validSigningMethods = []string{"HS256", "HS384", "HS512"}

	// Ensure Claims implements WebhookClaims
	_ Claims = (*WebhookClaims)(nil)
)

// New creates a SecureWebhookToken with the given issuer, event name, and data.
// Can be further customized with additional Option parameters.
// See Option for available functional parameters.
func New(issuer, event string, data any, opts ...Option) *SecureWebhookToken {
	claims := NewWebhookClaims(issuer, event, data)
	return NewWithClaims(&claims, opts...)
}

// NewWithClaims creates a new SecureWebhookToken with the given Claims object.
// Must be a pointer to an instance of WebhookClaims or a custom Claims instance, which embeds the WebhookClaims.
func NewWithClaims(c Claims, opts ...Option) *SecureWebhookToken {
	if c == nil {
		panic(ErrMissingClaims)
	}

	swt := &SecureWebhookToken{token: &jwt.Token{Claims: c}}
	for _, opt := range opts {
		if opt == nil {
			panic(ErrInvalidOption)
		}
		opt(swt)
	}

	// In case the signingMethod was set to nil via WithSigningMethod.
	if swt.token.Method == nil {
		swt.token.Method = jwt.SigningMethodHS256
	}

	// Disallow "none" JWT signing algorithm.
	if swt.token.Method.Alg() == "none" {
		panic(jwt.NoneSignatureTypeDisallowedError)
	}

	// Create the JWT
	swt.token = jwt.NewWithClaims(swt.token.Method, swt.token.Claims)
	return swt
}

// NewWebhookClaims creates WebhookClaims with a given issuer, event name and data, and the default registered claims.
func NewWebhookClaims(issuer, event string, data any) WebhookClaims {
	return WebhookClaims{
		Webhook: Webhook{
			Event: event,
			Data:  data,
		},
		RegisteredClaims: newRegClaims(issuer),
	}
}

type HandlerOptions struct {
	MaxBodySize int64
}

// NewHandlerFunc Creates a new http.HandlerFunc which will process an incoming
// webhook request and pass the token, if valid, to the given handleFn.
func NewHandlerFunc(secret []byte, handleFn func(*SecureWebhookToken) error, opts *HandlerOptions) http.HandlerFunc {
	var (
		token  *SecureWebhookToken
		whData WebhookData
		err    error
	)

	if handleFn == nil {
		panic("valid handler function is required")
	}

	if opts == nil {
		opts = &HandlerOptions{
			MaxBodySize: defaultMaxBodySize,
		}
	}

	logger := slog.Default().With("package", "github.com/SecureWebhookToken/swt")
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead, http.MethodPost:
			authHeader := r.Header.Get("Authorization")
			res := strings.Split(authHeader, "Bearer ")
			if len(res) != 2 {
				logger.Warn(fmt.Sprintf("invalid authorization header: %s", authHeader), "request", r)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			tokenStr := strings.TrimSpace(res[1])
			token, err = Parse(tokenStr, secret)
			if err != nil {
				logger.Warn(fmt.Sprintf("parse token error: %v", err), "request", r)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		default:
			logger.Warn(fmt.Sprintf("method not allowed: %s", r.Method), "request", r)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Handle POST method differently
		if r.Method == http.MethodPost {
			if r.ContentLength == -1 {
				logger.Error("unknown content length", "error", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			wh, _ := token.Claims().GetWebhook()
			rawData, err := json.Marshal(wh.Data)
			if err != nil {
				logger.Error("failed to parse webhook data", "error", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			err = json.Unmarshal(rawData, &whData)
			if err != nil {
				logger.Error("failed to parse webhook data", "error", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if whData.Size != r.ContentLength {
				logger.Error(fmt.Sprintf("wrong body size! expect content length of %d but got %d", whData.Size, r.ContentLength))
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Limit the request body to a given size to prevent wasting server resources by malicious clients
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, opts.MaxBodySize))

			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				logger.Error("max body size reached", "error", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err != nil {
				logger.Error("failed to read body", "error", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			err = validateBody(&whData, body)
			if err != nil {
				logger.Error("failed to validate signature", "error", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Override the webhook data with the data from the request body
			token.Claims().wc().Webhook.Data = body
		}

		// Pass the valid token to the handler function
		err = handleFn(token)
		if err != nil {
			logger.Error("handleFn error!", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// Parse parses a given token string, verifies it and returns a SecureWebhookToken if successful.
func Parse(tokenStr string, key any) (*SecureWebhookToken, error) {
	return ParseWithClaims(tokenStr, &WebhookClaims{}, key)
}

// ParseWithClaims parses a given token string and given claims, verifies it and returns a SecureWebhookToken if successful.
func ParseWithClaims(tokenStr string, claims Claims, key any) (*SecureWebhookToken, error) {
	var (
		swt = &SecureWebhookToken{}
		err error
	)

	if claims == nil {
		return nil, jwt.ErrTokenInvalidClaims
	}

	swt.token, err = jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(token *jwt.Token) (any, error) {
			return key, nil
		},
		jwt.WithValidMethods(validSigningMethods),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	if err != nil {
		return nil, err
	}

	return swt, nil
}

// SecureWebhookToken is a structure for secure webhook tokens.
// Currently, it implements symmetrical signatures based on HMAC-SHA for example purposes only.
// If the Internet-Draft is accepted, other methods will be implemented in the future.
type SecureWebhookToken struct {
	token *jwt.Token
}

// Algorithm returns the used SigningMethod algorithm.
func (swt *SecureWebhookToken) Algorithm() string {
	if swt.token == nil {
		panic(ErrInvalidToken)
	}
	return swt.token.Method.Alg()
}

// Claims return all token Claims.
// If no custom WebhookClaims have been set with NewWithClaims(), then the underlying type will be *WebhookClaims.
func (swt *SecureWebhookToken) Claims() Claims {
	if swt.token == nil {
		panic(ErrInvalidToken)
	}
	return swt.token.Claims.(Claims)
}

// ID convenient method for accessing the ID of the SecureWebhookToken.
func (swt *SecureWebhookToken) ID() string {
	return swt.Claims().wc().ID
}

// Issuer convenient method for accessing the Issuer claim of the SecureWebhookToken.
func (swt *SecureWebhookToken) Issuer() string {
	return swt.Claims().wc().Issuer
}

// Webhook convenient method for accessing the Webhook claim of the SecureWebhookToken.
func (swt *SecureWebhookToken) Webhook() Webhook {
	return swt.Claims().wc().Webhook
}

// SignedString returns the encoded and signed SecureWebhookToken as a JWT string.
func (swt *SecureWebhookToken) SignedString(key any) (string, error) {
	if swt.token == nil {
		return "", ErrInvalidToken
	}

	// Validate claims before signing
	if err := swt.Validate(); err != nil {
		return "", err
	}
	return swt.token.SignedString(key)
}

// Valid returns true only if the SecureWebhookToken has been created
// via Parse method and successfully been validated.
func (swt *SecureWebhookToken) Valid() bool {
	if swt.token == nil {
		return false
	}
	return swt.token.Valid
}

// Validate validates the Claims of the SecureWebhookToken.
func (swt *SecureWebhookToken) Validate() error {
	v := jwt.NewValidator(
		jwt.WithValidMethods(validSigningMethods),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	return v.Validate(swt.Claims())
}

// String implements the Stringer interface for returning the SecureWebhookToken as a JSON string.
func (swt *SecureWebhookToken) String() string {
	out, _ := json.MarshalIndent(
		struct {
			Header    map[string]any `json:"header"`
			Payload   jwt.Claims     `json:"payload"`
			Signature string         `json:"signature"`
			Validated bool           `json:"validated"`
		}{
			Header:    swt.token.Header,
			Payload:   swt.token.Claims,
			Signature: swt.token.EncodeSegment(swt.token.Signature),
			Validated: swt.token.Valid,
		},
		"",
		"  ",
	)

	return string(out)
}

type Webhook struct {
	Event string `json:"event"` // Event name. Should have the form EVENT_NAME.ACTIVITY (e.g., user.created or pull_request.merged)
	Data  any    `json:"data,omitempty"`
}

type WebhookData struct {
	Hash    string `json:"hash"`              // Hash string produced by the used HashAlg or sha3-256 by default
	HashAlg string `json:"hashAlg,omitempty"` // Hash algorithm is used to verify data integrity
	Size    int64  `json:"size"`              // Size of the payload in bytes
}

type Claims interface {
	GetID() (string, error)
	GetWebhook() (Webhook, error)
	wc() *WebhookClaims
	jwt.Claims
}

type WebhookClaims struct {
	Webhook Webhook `json:"webhook"`
	jwt.RegisteredClaims
}

// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
func (wc *WebhookClaims) GetID() (string, error) {
	return wc.ID, nil
}

// the `webhook` (SWT) claim. See https://www.ietf.org/archive/id/draft-knauer-secure-webhook-token-00.html#name-iana-considerations
func (wc *WebhookClaims) GetWebhook() (Webhook, error) {
	return wc.Webhook, nil
}

// MapClaims will convert a WebhookClaims object into jwt.MapClaims
// Can easily be used with the golang-jwt package for creating JWTs directly if desired.
func (wc *WebhookClaims) MapClaims() jwt.MapClaims {
	mc := map[string]any{
		"aud":     wc.Audience,
		"sub":     wc.Subject,
		"jti":     wc.ID,
		"iss":     wc.Issuer,
		"webhook": wc.Webhook,
	}
	if wc.ExpiresAt != nil {
		mc["exp"] = float64(wc.ExpiresAt.Unix())
	}
	if wc.IssuedAt != nil {
		mc["iat"] = float64(wc.IssuedAt.Unix())
	}
	if wc.NotBefore != nil {
		mc["nbf"] = float64(wc.NotBefore.Unix())
	}
	return mc
}

// Validate implements the jwt.ClaimsValidator interface to perform further required validation on specific claims.
func (wc *WebhookClaims) Validate() error {
	if wc.Issuer == "" {
		return fmt.Errorf("%w: iss: must not be empty", jwt.ErrTokenInvalidIssuer)
	}

	if wc.IssuedAt == nil {
		return fmt.Errorf("%w: iat", jwt.ErrTokenRequiredClaimMissing)
	}

	if wc.ExpiresAt == nil {
		return fmt.Errorf("%w: exp", jwt.ErrTokenRequiredClaimMissing)
	}

	if wc.NotBefore == nil {
		return fmt.Errorf("%w: nbf", jwt.ErrTokenRequiredClaimMissing)
	}

	if wc.Webhook.Event == "" {
		return fmt.Errorf("%w: %s: must contain an event", jwt.ErrTokenInvalidClaims, webhookClaim)
	}

	if wc.ID == "" {
		return fmt.Errorf("%w: jti: must not be empty! a uuid or similar is recommended", jwt.ErrTokenInvalidId)
	}

	return nil
}

// wc is a helper method for overriding the default claims with functional options.
func (wc *WebhookClaims) wc() *WebhookClaims {
	return wc
}

// HashSum computes the hash sum for a given hashAlg and the body to be sent via http.MethodPost request.
func HashSum(hashAlg string, body []byte) (string, error) {
	var hash string

	if hashAlg == "" {
		hashAlg = defaultHashAlgorithm
	}

	switch strings.ToUpper(hashAlg) {
	case SHA256:
		hash = fmt.Sprintf("%x", sha256.Sum256(body))
	case SHA384:
		hash = fmt.Sprintf("%x", sha512.Sum384(body))
	case SHA512:
		hash = fmt.Sprintf("%x", sha512.Sum512(body))
	case SHA3_256:
		hash = fmt.Sprintf("%x", sha3.Sum256(body))
	case SHA3_384:
		hash = fmt.Sprintf("%x", sha3.Sum384(body))
	case SHA3_512:
		hash = fmt.Sprintf("%x", sha3.Sum512(body))
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedHashAlgorithm, hashAlg)
	}

	return hash, nil
}

// validateBody validates the given body against the used hash function and signature.
func validateBody(whData *WebhookData, body []byte) error {
	hash, err := HashSum(whData.HashAlg, body)
	if err != nil {
		return err
	}
	if hash != whData.Hash {
		return ErrInvalidData
	}

	return nil
}

// newRegClaims creates jwt.RegisteredClaims with sensible defaults and the required issuer (iss) claim.
func newRegClaims(issuer string) jwt.RegisteredClaims {
	now := time.Now()
	return jwt.RegisteredClaims{
		ID:        uuid.NewString(),
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(defaultExpiration)),
		NotBefore: jwt.NewNumericDate(now),
	}
}
