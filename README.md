# stackpath-urlauth
Golang library to sign Hgihwinds CDN URLs.  This prevents tampering and allows for automatic expiration of URLs.

## Example
```go
import ("github.com/muxinc/highwinds-urlauth/urlauth")

inputURL := "https://www.example.com/foo?client_id=abc123&foo=bar"
secret := "supersecret"
expirationTime := startTime.Add(time.Hour * 6)
signedURL, err := urlauth.SignURL(inputURL, secret, expirationTime)
```
