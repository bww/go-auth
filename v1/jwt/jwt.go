package jwt

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bww/go-auth/v1"

	"github.com/bww/go-acl/v1"
	"github.com/bww/go-ident/v1"
	"github.com/golang-jwt/jwt/v5"
)

const (
	header = "Authorization"
	prefix = "JWT "
)

type Claims struct {
	jwt.RegisteredClaims
	Realm  acl.Realm  `json:"realm,omitempty"`
	Scopes acl.Scopes `json:"scopes,omitempty"`
}

type provider struct {
	secret []byte
}

func New(secret []byte) provider {
	return provider{secret}
}

func (a provider) keyfunc(tok *jwt.Token) (interface{}, error) {
	now := time.Now()
	if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("%w: Unexpected signing method: %v", auth.ErrUnauthorized, tok.Header["alg"])
	}
	if claims, ok := tok.Claims.(*Claims); !ok {
		return nil, fmt.Errorf("%w: Unexpected claims type: %T", auth.ErrUnauthorized, tok.Claims)
	} else if claims.ExpiresAt != nil && claims.ExpiresAt.Before(now) {
		return nil, fmt.Errorf("%w: Token is expired", auth.ErrUnauthorized)
	}
	return a.secret, nil
}

func (a provider) Sign(claims *Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.secret)
}

func (a provider) Authorize(realm acl.Realm, scopes acl.Scopes, req *http.Request) error {
	tok, err := a.Sign(&Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       ident.New().String(),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Realm:  realm,
		Scopes: scopes,
	})
	if err != nil {
		return err
	}
	return a.authorize(tok, req)
}

func (a provider) authorize(tok string, req *http.Request) error {
	req.Header.Set(header, prefix+tok)
	return nil
}

func (a provider) Validate(realm acl.Realm, require acl.Scopes, req *http.Request) error {
	v := req.Header.Get(header)
	if v == "" {
		return auth.ErrUnauthorized
	}
	if !strings.HasPrefix(v, prefix) {
		return fmt.Errorf("%w: Invalid authorization method", auth.ErrUnauthorized)
	}
	authdata := []byte(v[len(prefix):])
	tok, err := jwt.ParseWithClaims(string(authdata), &Claims{}, a.keyfunc)
	if errors.Is(err, jwt.ErrSignatureInvalid) {
		return fmt.Errorf("%w: Invalid signature", auth.ErrUnauthorized)
	} else if err != nil {
		return err
	}
	if tok == nil || !tok.Valid {
		return fmt.Errorf("%w: Invalid token", auth.ErrUnauthorized)
	}
	claims, ok := tok.Claims.(*Claims)
	if !ok {
		return fmt.Errorf("%w: Claims have invalid format: %v < %v", auth.ErrForbidden, claims.Scopes, require)
	}
	if !claims.Realm.Contains(realm) {
		return fmt.Errorf("%w: Claim realm is not satisfied: <%v> does not contain <%v>", auth.ErrForbidden, claims.Realm, realm)
	}
	if !claims.Scopes.Satisfies(require...) {
		return fmt.Errorf("%w: Claim scopes are not satisfied: %v < %v in <%v>", auth.ErrForbidden, claims.Scopes, require, realm)
	}
	return nil
}
