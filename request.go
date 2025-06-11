package swt

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/gabriel-vasile/mimetype"
)

// BuildRequest can be used to create an http.Request for sending a SecureWebhookToken via HEAD or POST request,
// depending on the size and value of the provided data.
func BuildRequest(url, issuer, event string, data []byte, key any) (*http.Request, error) {
	if len(data) <= HeadMaxDataSize {
		return BuildHeadRequest(url, issuer, event, data, key)
	}
	return BuildPostRequest(url, issuer, event, data, key)
}

// BuildHeadRequest creates an http.Request with http.MethodHead independently of data length.
// Should only be used if you've good reasons not to stick to the suggested HeadMaxDataSize as
// depicted in the SecureWebhookToken draft.
func BuildHeadRequest(url, issuer, event string, data []byte, key any) (*http.Request, error) {
	var (
		claims WebhookClaims
		req    *http.Request
		err    error
	)

	if data != nil && !isValidJson(data) {
		return nil, ErrInvalidJSON
	}
	claims = NewWebhookClaims(issuer, event, data)

	swt := NewWithClaims(&claims)
	tokenStr, err := swt.SignedString(key)
	if err != nil {
		return nil, err
	}
	req, err = http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+tokenStr)
	return req, nil
}

// BuildPostRequest creates an http.Request with http.MethodPost independently of data length.
// Can be used e.g., when sending a SecureWebhookToken with data of a type which differs
// from JSON or a data size less than the HeadMaxDataSize.
func BuildPostRequest(url, issuer, event string, data []byte, key any) (*http.Request, error) {
	var (
		claims WebhookClaims
		req    *http.Request
		err    error
	)

	hash, err := HashSum(SHA3_256, data)
	if err != nil {
		return nil, err
	}
	claims = NewWebhookClaims(issuer, event, WebhookData{
		Hash:    hash,
		HashAlg: SHA3_256,
		Size:    int64(len(data)),
	})

	swt := NewWithClaims(&claims)
	tokenStr, err := swt.SignedString(key)
	if err != nil {
		return nil, err
	}

	req, err = http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	mType := mimetype.Detect(data)
	if mType != nil {
		req.Header.Set("Content-Type", mType.String())
	} else {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	return req, nil
}

// isValidJson returns true only if data can be successfully unmarshalled into a map[string]any.
func isValidJson(data []byte) bool {
	return json.Unmarshal(data, &map[string]any{}) == nil
}
