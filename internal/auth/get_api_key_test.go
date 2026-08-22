package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers   http.Header
		wantKey   string
		wantErr   error
		wantAnErr bool
	}{
		"valid api key": {
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
		},
		"no authorization header": {
			headers:   http.Header{},
			wantErr:   ErrNoAuthHeaderIncluded,
			wantAnErr: true,
		},
		"empty authorization header": {
			headers:   http.Header{"Authorization": []string{""}},
			wantErr:   ErrNoAuthHeaderIncluded,
			wantAnErr: true,
		},
		"wrong scheme": {
			headers:   http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			wantAnErr: true,
		},
		"missing key after scheme": {
			headers:   http.Header{"Authorization": []string{"ApiKey"}},
			wantAnErr: true,
		},
		"empty key after scheme": {
			headers:   http.Header{"Authorization": []string{"ApiKey "}},
			wantAnErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)

			if tc.wantAnErr {
				if err == nil {
					t.Fatalf("GetAPIKey() expected an error, got key %q", got)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("GetAPIKey() error = %v, want %v", err, tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("GetAPIKey() unexpected error: %v", err)
			}
			if got != tc.wantKey {
				t.Errorf("GetAPIKey() = %q, want %q", got, tc.wantKey)
			}
		})
	}
}
