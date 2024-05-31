package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bww/go-auth/v1/jwt"

	"github.com/bww/go-acl/v1"
	"github.com/bww/go-ident/v1"
	"github.com/bww/go-util/v1/crypto"
	jwtlib "github.com/golang-jwt/jwt/v5"
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
		fMethod = cmdline.String("method", JWT, "The authorization method to use.")
		fSecret = cmdline.String("secret", "", "The secret to use.")
		fSalt   = cmdline.String("salt", "", "The salt to use.")
		fHeader = cmdline.Bool("header", false, "Output the Authorization header.")
	)
	cmdline.Parse(args[1:])

	if *fSecret == "" {
		return errors.New("Secret is required")
	} else if *fSalt == "" {
		return errors.New("Salt is required")
	}

	secret := crypto.GenerateKey(*fSecret, *fSalt, crypto.SHA1)

	var opts Options
	if *fHeader {
		opts |= OptionHeader
	}

	switch m := *fMethod; m {
	case JWT:
		return authJWT(opts, secret, cmdline.Args())
	default:
		return fmt.Errorf("Unsupported method: %s", m)
	}
}

func authJWT(opts Options, secret []byte, args []string) error {
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
