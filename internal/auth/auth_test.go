package auth

import (
	"net/http"
	"testing"
)

func TestAuthGetAPIKey(t *testing.T) {

	t.Run("GetAPIKey returns error when no auth header is included", func(t *testing.T) {
		headers := http.Header{}
		_, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
		}
	})

	t.Run("GetAPIKey returns error when auth header is malformed", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "InvalidHeader")
		_, err := GetAPIKey(headers)
		if err == nil || err.Error() != "malformed authorization header" {
			t.Errorf("expected 'malformed authorization header' error, got %v", err)
		}
	})

	t.Run("GetAPIKey returns API key when valid auth header is included", func(t *testing.T) {
		headers := http.Header{}
		expectedAPIKey := "valid_api_key"
		headers.Set("Authorization", "ApiKey "+expectedAPIKey)
		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if apiKey != expectedAPIKey {
			t.Errorf("expected API key %v, got %v", expectedAPIKey, apiKey)
		}
	})
}
