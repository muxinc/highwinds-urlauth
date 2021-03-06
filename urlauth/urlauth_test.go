package urlauth

import (
	"testing"
	"time"
)

var (
	expirationTime = time.Unix(1544720086, 0)
)

func TestSignURL(t *testing.T) {
	type args struct {
		url            string
		secret         string
		expirationTime *time.Time
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "Empty URL",
			args:    args{},
			wantErr: true,
		},
		{
			name:    "Empty secret",
			args:    args{url: "https://www.example.com/foo"},
			wantErr: true,
		},
		{
			name: "Invalid URL",
			args: args{
				url:    "*&#$%",
				secret: "supersecret",
			},
			wantErr: true,
		},
		{
			name: "Valid URL without an expiration time",
			args: args{
				url:    "https://www.example.com/foo?client_id=abc123",
				secret: "supersecret",
			},
			wantErr: true,
		},
		{
			name: "Valid URL with a query param",
			args: args{
				url:    "https://www.example.com/foo?bar=1",
				secret: "supersecret", expirationTime: &expirationTime,
			},
			want: "https://www.example.com/foo?bar=1&e=1544720086&st=b805320d706d8501124ad907a505fbeb",
		},
		{
			name: "URL with multiple query params where one of the params has an equal sign and no value",
			args: args{
				url:    "https://www.example.com/foo?bar=&baz=ok",
				secret: "supersecret", expirationTime: &expirationTime,
			},
			wantErr: true,
		},
		{
			name: "URL with multiple query params where one of the params has an equal sign and no value",
			args: args{
				url:    "https://www.example.com/foo?bar=ok&baz=",
				secret: "supersecret", expirationTime: &expirationTime,
			},
			wantErr: true,
		},
		{
			name: "Valid URL without a query-param",
			args: args{
				url:            "https://www.example.com/foo",
				secret:         "supersecret",
				expirationTime: &expirationTime,
			},
			want: "https://www.example.com/foo?e=1544720086&st=f08d6d9904adfd6a4f6287b695b68a8e",
		},
		{
			name: "Valid URL path without an expiration time",
			args: args{
				url:    "/foo?client_id=abc123",
				secret: "supersecret",
			},
			wantErr: true,
		},
		{
			name: "Valid URL path with a query param",
			args: args{
				url:            "/foo?bar=1",
				secret:         "supersecret",
				expirationTime: &expirationTime,
			},
			want: "/foo?bar=1&e=1544720086&st=b805320d706d8501124ad907a505fbeb",
		},
		{
			name: "Valid URL path without a query-param",
			args: args{
				url:            "/foo",
				secret:         "supersecret",
				expirationTime: &expirationTime,
			},
			want: "/foo?e=1544720086&st=f08d6d9904adfd6a4f6287b695b68a8e",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignURL(tt.args.url, tt.args.secret, tt.args.expirationTime)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Benchmark_URLAuth_SignURL(b *testing.B) {
	for n := 0; n < b.N; n++ {
		if _, err := SignURL("https://www.example.com/foo?bar=1", "supersecret", &expirationTime); err != nil {
			b.Logf("URLAuth.SignURL() error = %v", err)
		}
	}
}
