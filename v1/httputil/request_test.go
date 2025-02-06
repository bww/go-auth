package httputil

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCanonicalRequests(t *testing.T) {
	tests := []struct {
		Method  string
		URI     string
		Params  url.Values
		Options []CanonicalRequestOption
		Expect  string
	}{
		{
			Method: "GET",
			URI:    "/hello",
			Params: url.Values{},
			Expect: "GET;/hello;",
		},
		{
			Method: "GET",
			URI:    "/hello",
			Params: url.Values{"p1": []string{"A"}, "p2": []string{"B"}},
			Expect: "GET;/hello;p1=A&p2=B",
		},
		{
			Method: "GET",
			URI:    "/hello",
			Params: url.Values{"p1": []string{"X", "A"}, "p2": []string{"Z", "B"}, "jwt": []string{"<token>"}},
			Expect: "GET;/hello;p1=A,X&p2=B,Z",
		},
		{
			Method:  "GET",
			URI:     "/hello",
			Params:  url.Values{"p1": []string{"X", "A"}, "p2": []string{"Z", "B"}, "jwt": []string{"<token>"}},
			Options: []CanonicalRequestOption{WithExcludedParams("p1")},
			Expect:  "GET;/hello;p2=B,Z",
		},
	}
	for _, test := range tests {
		crd := CanonicalRequestComponents(test.Method, test.URI, test.Params, test.Options...)
		assert.Equal(t, test.Expect, crd)
	}
}
