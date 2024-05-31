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
	Scopes acl.Scopes `json:"scopes,omitempty"`
}

type authorizer struct {
	secret []byte
}

func New(secret []byte) authorizer {
	return authorizer{secret}
}

func (a authorizer) keyfunc(tok *jwt.Token) (interface{}, error) {
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

func (a authorizer) Assert(require acl.Scopes, authorization []byte) error {
	tok, err := jwt.ParseWithClaims(string(authorization), &Claims{}, a.keyfunc)
	if errors.Is(err, jwt.ErrSignatureInvalid) {
		return fmt.Errorf("%w: Invalid signature", auth.ErrUnauthorized)
	} else if err != nil {
		return err
	}
	if tok == nil || !tok.Valid {
		return fmt.Errorf("%w: Invalid token", auth.ErrUnauthorized)
	}
	if claims := tok.Claims.(*Claims); claims.Scopes.Satisfies(require...) {
		return nil
	} else {
		return fmt.Errorf("%w: Claims are not satisfied: %v < %v", auth.ErrForbidden, claims.Scopes, require)
	}
}

func (a authorizer) Sign(claims *Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.secret)
}

func (a authorizer) Authorize(scopes acl.Scopes, req *http.Request) error {
	tok, err := a.Sign(&Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       ident.New().String(),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Scopes: scopes,
	})
	if err != nil {
		return err
	}
	return a.authorize(tok, req)
}

func (a authorizer) authorize(tok string, req *http.Request) error {
	req.Header.Set(header, prefix+tok)
	return nil
}

func (a authorizer) Verify(require acl.Scopes, req *http.Request) error {
	v := req.Header.Get(header)
	if v == "" {
		return auth.ErrUnauthorized
	}
	if !strings.HasPrefix(v, prefix) {
		return fmt.Errorf("%w: Invalid authorization method", auth.ErrUnauthorized)
	}
	return a.Assert(require, []byte(v[len(prefix):]))
}
