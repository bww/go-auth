package httputil

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const jwtParam = "jwt" // the JWT parameter; we must ignore this

func CanonicalRequest(req *http.Request) string {
	return CanonicalRequestComponents(req.Method, req.URL.Path, req.URL.Query())
}

func CanonicalRequestComponents(method, resource string, params url.Values) string {
	b := &strings.Builder{}
	b.WriteString(method)
	b.WriteString(";")
	b.WriteString(resource)
	b.WriteString(";")

	q := params
	keys := make([]string, 0, len(q))
	vals := make(map[string][]string)

	for k, v := range q {
		if k != jwtParam {
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
