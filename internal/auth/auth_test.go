package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

//"github.com/stretchr/testify/assert"

func TestGetApiKey(t *testing.T) {
	tests := map[string]struct {
		inputHeader string
		inputVal    string
		want        string
		wantErr     string
	}{
		"Valid ApiKey": {
			inputHeader: "Authorization",
			inputVal:    "ApiKey 12345abc",
			want:        "12345abc",
			wantErr:     "",
		},
		"No Authorization Header": {
			inputHeader: "",
			inputVal:    "",
			want:        "",
			wantErr:     ErrNoAuthHeaderIncluded.Error(),
		},
		"Wrong Prefix (Bearer)": {
			inputHeader: "Authorization",
			inputVal:    "Bearer some-token",
			want:        "",
			wantErr:     "malformed authorization header",
		},
		"Only Prefix No Token": {
			inputHeader: "Authorization",
			inputVal:    "ApiKey",
			want:        "",
			wantErr:     "malformed authorization header",
		},
		"Random Header Name": {
			inputHeader: "X-Api-Key",
			inputVal:    "12345",
			want:        "",
			wantErr:     ErrNoAuthHeaderIncluded.Error(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			header := http.Header{}
			if tc.inputHeader != "" {
				header.Set(tc.inputHeader, tc.inputVal)
			}

			got, err := GetAPIKey(header)
			require.Equal(t, tc.want, got)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Equal(t, tc.wantErr, err.Error())
			}
		})
	}
}
