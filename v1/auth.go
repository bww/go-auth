package auth

import (
	"errors"
	"net/http"

	"github.com/bww/go-acl/v1"
)

var (
	ErrUnauthorized = errors.New("Unauthorized")
	ErrForbidden    = errors.New("Forbidden")
)

type Authorizer interface {
	Authorize(acl.Realm, acl.Scopes, *http.Request) error
}

type Validator interface {
	Validate(acl.Realm, acl.Scopes, *http.Request) error
}
