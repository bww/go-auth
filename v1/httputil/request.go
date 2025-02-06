package httputil

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const jwtParam = "jwt" // the JWT parameter; we must ignore this

type CanonicalRequestConfig struct {
	ExcludeParams []string
}

func (c CanonicalRequestConfig) WithOptions(opts []CanonicalRequestOption) CanonicalRequestConfig {
	for _, opt := range opts {
		c = opt(c)
	}
	return c
}

func (c CanonicalRequestConfig) ExcludedParams() map[string]struct{} {
	// If params are not defined, we use the default set, which is jus the JWT parameter itself
	if c.ExcludeParams == nil {
		return map[string]struct{}{jwtParam: {}}
	}
	x := make(map[string]struct{})
	for _, e := range c.ExcludeParams {
		x[e] = struct{}{}
	}
	return x
}

type CanonicalRequestOption func(CanonicalRequestConfig) CanonicalRequestConfig

func WithExcludedParams(names ...string) CanonicalRequestOption {
	return func(c CanonicalRequestConfig) CanonicalRequestConfig {
		c.ExcludeParams = append(names, jwtParam) // always include the JWT param
		return c
	}
}

func CanonicalRequest(req *http.Request, opts ...CanonicalRequestOption) string {
	return CanonicalRequestComponents(req.Method, req.URL.Path, req.URL.Query(), opts...)
}

func CanonicalRequestComponents(method, resource string, params url.Values, opts ...CanonicalRequestOption) string {
	return CanonicalRequestComponentsWithConfig(method, resource, params, CanonicalRequestConfig{}.WithOptions(opts))
}

// CanonicalRequestComponentsWithConfig is the lowest level primitive of this
// method; you should use CanonicalRequest or CanonicalRequestComponents
// instead.
func CanonicalRequestComponentsWithConfig(method, resource string, params url.Values, conf CanonicalRequestConfig) string {
	b := &strings.Builder{}
	b.WriteString(method)
	b.WriteString(";")
	b.WriteString(resource)
	b.WriteString(";")

	q := params
	keys := make([]string, 0, len(q))
	vals := make(map[string][]string)

	excl := conf.ExcludedParams()
	for k, v := range q {
		if _, ok := excl[k]; !ok {
			sort.Strings(v)
			keys = append(keys, k)
			vals[k] = v
		}
	}

	sort.Strings(keys)
	for i, e := range keys {
		if i > 0 {
			b.WriteString("&")
		}
		b.WriteString(url.QueryEscape(e))
		b.WriteString("=")
		v := vals[e]
		for i, x := range v {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(url.QueryEscape(x))
		}
	}

	return b.String()
}
