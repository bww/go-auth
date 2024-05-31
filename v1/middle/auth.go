package middle

import (
	syserr "errors"
	"net/http"

	"github.com/bww/go-auth/v1"

	"github.com/bww/go-acl/v1"
	"github.com/bww/go-rest/v1/errors"
	"github.com/bww/go-router/v1"
)

func ACL(azr auth.Authorizer, require acl.Scopes, wrap router.Handler) router.Handler {
	return func(req *router.Request, cxt router.Context) (*router.Response, error) {
		err := azr.Verify(require, (*http.Request)(req))
		if syserr.Is(err, auth.ErrUnauthorized) {
			return nil, errors.New(http.StatusUnauthorized, "Unauthorized", err)
		} else if syserr.Is(err, auth.ErrForbidden) {
			return nil, errors.New(http.StatusForbidden, "Forbidden", err)
		} else if err != nil {
			return nil, errors.New(http.StatusInternalServerError, "An error occurred", err)
		} else {
			return wrap(req, cxt)
		}
	}
}
