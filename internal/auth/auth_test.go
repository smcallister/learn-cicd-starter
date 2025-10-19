package auth

import (
	"errors"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		name      string
		headers   map[string][]string
		wantKey   string
		wantError error
	}

	tests := []test {
		{
			name:      "No Authorization Header",
			headers:   map[string][]string{},
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - Missing ApiKey Prefix",
			headers: map[string][]string{
				"Authorization": {"Bearer somekey"},
			},
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - No Key Provided",
			headers: map[string][]string{
				"Authorization": {"ApiKey"},
			},
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name: "Valid Authorization Header",
			headers: map[string][]string{
				"Authorization": {"ApiKey validkey123"},
			},
			wantKey:   "validkey123",
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotError := GetAPIKey(tt.headers)
			if (gotKey != tt.wantKey) || !reflect.DeepEqual(gotError, tt.wantError) {
				t.Errorf("GetAPIKey() gotKey = %v, want %v; gotError = %v, want %v", gotKey, tt.wantKey, gotError, tt.wantError)
			}
		})
	}
}