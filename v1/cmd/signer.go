package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/bww/go-auth/v1/jwt"

	"github.com/bww/go-acl/v1"
	"github.com/bww/go-ident/v1"
	"github.com/bww/go-util/v1/crypto"
	jwtlib "github.com/golang-jwt/jwt/v5"
	flag "github.com/spf13/pflag"
)

const (
	JWT = "jwt"
)

type Options uint64

func (o Options) On(v Options) bool {
	return (o & v) == v
}

const (
	OptionHeader = 1 << iota
)

func main() {
	if err := app(os.Args); err != nil {
		fmt.Println("***", err)
		os.Exit(1)
	}
}

func app(args []string) error {
	cmd := args[0]
	cmdline := flag.NewFlagSet(cmd, flag.ExitOnError)

	var (
		method    string
		secret    string
		salt      string
		realmSpec string
		header    bool
	)

	cmdline.StringVar(&method, "method", JWT, "The authorization method to use.")
	cmdline.StringVar(&secret, "secret", "", "The secret to use.")
	cmdline.StringVar(&salt, "salt", "", "The salt to use.")
	cmdline.StringVar(&realmSpec, "realm", "", "The realm to use; if no realm is specified, the root realm is used.")
	cmdline.BoolVar(&header, "header", false, "Output the Authorization header.")

	cmdline.Parse(args[1:])

	if secret == "" {
		return errors.New("Secret is required; use: --secret <secret>")
	} else if salt == "" {
		return errors.New("Salt is required; use: --salt <salt>")
	}

	realm, err := acl.ParseRealm(realmSpec)
	if err != nil {
		return fmt.Errorf("Could not parse realm: %w", err)
	}

	key := crypto.GenerateKey(secret, salt, crypto.SHA1)

	var opts Options
	if header {
		opts |= OptionHeader
	}

	switch m := method; m {
	case JWT:
		return authJWT(opts, realm, key, cmdline.Args())
	default:
		return fmt.Errorf("Unsupported method: %s", m)
	}
}

func authJWT(opts Options, realm acl.Realm, secret []byte, args []string) error {
	var scopes acl.Scopes
	for _, e := range args {
		s, err := acl.ParseScope(e)
		if err != nil {
			return err
		}
		scopes = append(scopes, s)
	}

	a := jwt.New([]byte(secret))
	tok, err := a.Sign(&jwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			ID:       ident.New().String(),
			IssuedAt: jwtlib.NewNumericDate(time.Now()),
		},
		Realm:  realm,
		Scopes: scopes,
	})
	if err != nil {
		return err
	}

	if opts.On(OptionHeader) {
		fmt.Println("Authorization: JWT", tok)
	} else {
		fmt.Println(tok)
	}
	return nil
}
