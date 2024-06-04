package jwt

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/bww/go-auth/v1"

	"github.com/bww/go-acl/v1"
	"github.com/bww/go-ident/v1"
	errutil "github.com/bww/go-util/v1/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestJWTAuth(t *testing.T) {
	var (
		a1 = New([]byte("ABC123"))
		a2 = New([]byte("Another"))

		readonly  = acl.Scopes{acl.NewScope("foo", acl.Read)}
		readwrite = acl.Scopes{acl.NewScope("foo", acl.Read, acl.Write)}

		realm1 = errutil.Must(acl.ParseRealm("wk:000000"))
		realm2 = errutil.Must(acl.ParseRealm("wk:000000/pj:111111"))
		realm3 = errutil.Must(acl.ParseRealm("wk:111111"))
	)

	req1 := errutil.Must(http.NewRequest("GET", "/1", nil))
	assert.Nil(t, a1.Authorize(realm1, readonly, req1))
	assert.Nil(t, a1.Validate(realm2, readonly, req1))
	assert.ErrorIs(t, a1.Validate(realm2, readwrite, req1), auth.ErrForbidden)
	assert.ErrorIs(t, a1.Validate(realm3, readonly, req1), auth.ErrForbidden)
	assert.ErrorIs(t, a2.Validate(realm2, readonly, req1), auth.ErrUnauthorized)
	assert.ErrorIs(t, a2.Validate(realm2, readwrite, req1), auth.ErrUnauthorized)

	now := time.Now().Add(-time.Second * 2)
	tok1, err := a1.Sign(&Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        ident.New().String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now),
		},
		Realm:  realm1,
		Scopes: readonly,
	})
	assert.Nil(t, err)

	req2 := errutil.Must(http.NewRequest("GET", "/2", nil))
	assert.Nil(t, a1.authorize(tok1, req2))
	assert.ErrorIs(t, a1.Validate(realm2, readonly, req2), auth.ErrUnauthorized)

	tok2, err := a1.Sign(&Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       ident.New().String(),
			IssuedAt: jwt.NewNumericDate(now),
		},
	})
	assert.Nil(t, err)

	req3 := errutil.Must(http.NewRequest("GET", "/3", nil))
	assert.Nil(t, a1.authorize(tok2, req3))
	assert.ErrorIs(t, a1.Validate(realm2, readonly, req3), auth.ErrForbidden)
	assert.NoError(t, a1.Validate(realm2, nil, req3))

	req4 := errutil.Must(http.NewRequest("GET", "/4", nil))
	req4.Header.Set("Authorization", "WRONG the_token")
	assert.Equal(t, auth.ErrUnauthorized, errors.Unwrap(a1.Validate(realm2, readonly, req4)))

}
