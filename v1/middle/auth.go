package middle

import (
	syserr "errors"
	"net/http"

	"github.com/bww/go-auth/v1"

	"github.com/bww/go-acl/v1"
	"github.com/bww/go-rest/v2/errors"
	"github.com/bww/go-router/v2"
)

// A middleware that provides access control via an authorizer
func ACL(azr auth.Validator, realm acl.Realm, require acl.Scopes) router.Middle {
	return router.MiddleFunc(func(wrap router.Handler) router.Handler {
		return func(req *router.Request, cxt router.Context) (*router.Response, error) {
			var resterr *errors.Error
			err := azr.Validate(realm, require, (*http.Request)(req))
			if syserr.As(err, &resterr) {
				return nil, err // already a REST error; pass through
			} else if syserr.Is(err, auth.ErrUnauthorized) {
				return nil, errors.New(http.StatusUnauthorized, "Unauthorized", err)
			} else if syserr.Is(err, auth.ErrForbidden) {
				return nil, errors.New(http.StatusForbidden, "Forbidden", err)
			} else if err != nil {
				return nil, errors.New(http.StatusInternalServerError, "An error occurred", err)
			} else {
				return wrap(req, cxt)
			}
		}
	})
}
