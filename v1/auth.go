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
	Assert(acl.Scopes, []byte) error
	Authorize(acl.Scopes, *http.Request) error
	Verify(acl.Scopes, *http.Request) error
}
