package swt

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/gabriel-vasile/mimetype"
)

// Request represents a webhook request configuration for creating SecureWebhookTokens.
// It contains all the necessary information to build HTTP requests with embedded tokens.
type Request struct {
	URL     string // Target URL for the webhook request
	Issuer  string // JWT issuer claim (iss) - typically the service sending the webhook
	Event   string // Event name following EVENT_NAME.ACTIVITY format (e.g., "user.created")
	HashAlg string // Hash algorithm for POST requests (SHA-256, SHA3-256, etc.). Defaults to SHA3-256 if empty
	Data    []byte // Payload data to be sent with the request
}

// Build can be used to create an http.Request for creating and sending a SecureWebhookToken via HEAD or POST request,
// depending on the size and value of the provided data.
func (r *Request) Build(key any, opts ...Option) (*http.Request, error) {
	if len(r.Data) <= HeadMaxDataSize {
		return r.BuildHead(key, opts...)
	}
	return r.BuildPost(key, opts...)
}

// BuildHead creates an http.Request with http.MethodHead independently of data length.
// Should only be used if you've good reasons not to stick to the suggested HeadMaxDataSize as
// depicted in the SecureWebhookToken draft.
func (r *Request) BuildHead(key any, opts ...Option) (*http.Request, error) {
	var (
		claims WebhookClaims
		req    *http.Request
		err    error
	)

	if r.Data != nil && !json.Valid(r.Data) {
		return nil, ErrInvalidJSON
	}

	claims = NewWebhookClaims(r.Issuer, r.Event, r.Data)
	swt := NewWithClaims(&claims, opts...)
	tokenStr, err := swt.SignedString(key)
	if err != nil {
		return nil, err
	}

	req, err = http.NewRequest(http.MethodHead, r.URL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+tokenStr)
	return req, nil
}

// BuildPost creates an http.Request with http.MethodPost independently of data length.
// Can be used e.g., when creating and sending a SecureWebhookToken with data of a type which differs
// from JSON or a data size less than the HeadMaxDataSize.
func (r *Request) BuildPost(key any, opts ...Option) (*http.Request, error) {
	var (
		claims WebhookClaims
		req    *http.Request
		err    error
	)

	hash, err := HashSum(r.HashAlg, r.Data)
	if err != nil {
		return nil, err
	}
	claims = NewWebhookClaims(r.Issuer, r.Event, WebhookData{
		Hash:    hash,
		HashAlg: r.HashAlg,
		Size:    int64(len(r.Data)),
	})

	swt := NewWithClaims(&claims, opts...)
	tokenStr, err := swt.SignedString(key)
	if err != nil {
		return nil, err
	}

	req, err = http.NewRequest(http.MethodPost, r.URL, bytes.NewReader(r.Data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	mType := mimetype.Detect(r.Data)
	if mType != nil {
		req.Header.Set("Content-Type", mType.String())
	} else {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	return req, nil
}
