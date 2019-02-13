# highwinds-urlauth
Golang library to sign Highwinds CDN URLs.  This prevents tampering and allows for automatic expiration of URLs.

## Highwinds Configuration
Use the following settings in the Highwinds Striketracker `Content Access Authentication` section for URL Signing:

| Setting  | Value |
| ------------- | ------------- |
| URL Signature Name  | `st`  |
| Passphrase Name  | `secret`  |
| Expiration Name  | `e`  |

Of course, also configure a passphrase that matches the secret you plan to use during signing.

##  Usage Example
```go
import ("github.com/muxinc/highwinds-urlauth/urlauth")

inputURL := "https://www.example.com/foo?client_id=abc123&foo=bar"
secret := "supersecret"
expirationTime := time.Now().Add(time.Hour * 6)
signedURL, err := urlauth.SignURL(inputURL, secret, expirationTime)
```
