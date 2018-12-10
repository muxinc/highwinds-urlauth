package urlauth

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SignURL signs a given URL string using the supplied secret for verification by the Stackpath CDN.
func SignURL(plainURL, secret string, expirationTime *time.Time) (string, error) {
	if len(plainURL) == 0 {
		return "", errors.New("URL was empty, expected a non-empty URL for signing")
	}

	if len(secret) == 0 {
		return "", errors.New("Secret was empty, expected a non-empty secret for signing")
	}

	if expirationTime == nil {
		return "", errors.New("Expiration time was nil, expected a non-nil time for signing")
	}

	inputURL, err := url.Parse(plainURL)
	if err != nil {
		return "", fmt.Errorf("Error parsing plain URL prior to signing: %v", err)
	}

	// build up request path and query params for signing
	requestPathBuilder := &strings.Builder{}
	requestPathBuilder.WriteString(inputURL.Path)
	requestPathBuilder.WriteString("?")
	if inputURL.RawQuery != "" {
		requestPathBuilder.WriteString(inputURL.RawQuery)
		requestPathBuilder.WriteString("&")
	}

	expirationTimeSeconds := expirationTime.Unix()
	expirationSecondsStr := strconv.FormatInt(expirationTimeSeconds, 10)
	requestPathBuilder.WriteString(fmt.Sprintf("e=%s&secret=%s", expirationSecondsStr, secret))

	// calculate signature and URL-safe base64-encode
	digest := md5.Sum([]byte(requestPathBuilder.String()))
	signature := hex.EncodeToString(digest[:])

	// construct the new request query params with signature and expiration time
	queryParamsBuilder := &strings.Builder{}
	if inputURL.RawQuery != "" {
		queryParamsBuilder.WriteString(inputURL.RawQuery)
		queryParamsBuilder.WriteString("&")
	}
	queryParamsBuilder.WriteString(fmt.Sprintf("e=%s&st=%s", expirationSecondsStr, signature))
	inputURL.RawQuery = queryParamsBuilder.String()

	return inputURL.String(), nil
}
