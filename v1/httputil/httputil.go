package httputil

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

const (
	JWTParamName  = "jwt"
	JWTCookieName = "vs_authn"
)

var (
	ErrNoAuthorization   = fmt.Errorf("No authorization")
	ErrMalformedRequest  = fmt.Errorf("Authorization is malformed")
	ErrUnsupportedMethod = fmt.Errorf("Authorization method is not supported")
)

// Obtain the basic auth credential for the specified request
func BasicAuthCredential(req *http.Request) (string, string, error) {
	auth := req.Header.Get("Authorization")
	if auth != "" {
		return BasicAuthCredentialFromAuthorization(auth)
	}
	auth = req.URL.Query().Get("auth")
	if auth != "" {
		return BasicAuthCredentialFromAuthorizationData(auth)
	}
	return "", "", ErrNoAuthorization
}

// Obtain the basic auth credential for the specified authorization header
func BasicAuthCredentialFromAuthorization(auth string) (string, string, error) {
	header := strings.Fields(auth)
	if len(header) != 2 {
		return "", "", ErrMalformedRequest
	}
	method := strings.ToLower(header[0])
	if method != "basic" {
		return "", "", ErrUnsupportedMethod
	}
	return BasicAuthCredentialFromAuthorizationData(header[1])
}

// Obtain the basic auth credential for the specified authorization header data
func BasicAuthCredentialFromAuthorizationData(auth string) (string, string, error) {
	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", ErrMalformedRequest
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 2 {
		return "", "", ErrMalformedRequest
	}
	return parts[0], parts[1], nil
}

// Obtain a JWT token for the provided request
func JWTCredential(req *http.Request) (string, error) {
	auth := req.Header.Get("Authorization")
	if auth != "" {
		return JWTCredentialFromAuthorization(auth)
	}
	auth = req.URL.Query().Get(JWTParamName)
	if auth != "" {
		return auth, nil
	}
	cookie, err := req.Cookie(JWTCookieName)
	if err == nil {
		return cookie.Value, nil
	} else if err != http.ErrNoCookie {
		return "", err
	}
	return "", ErrNoAuthorization
}

// Obtain a JWT token for the provided authorization header
func JWTCredentialFromAuthorization(auth string) (string, error) {
	header := strings.Fields(auth)
	if len(header) != 2 {
		return "", ErrMalformedRequest
	}
	method := strings.ToLower(header[0])
	if method != "jwt" {
		return "", ErrUnsupportedMethod
	}
	return header[1], nil
}
