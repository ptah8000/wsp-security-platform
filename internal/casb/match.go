package casb

import (
	"mime"
	"net"
	"net/http"
	"path"
	"strings"
)

// hostMatches reports whether host (may include port) matches any suffix in suffixes.
// Matching is case-insensitive. A suffix "example.com" matches "example.com" and
// "sub.example.com". Suffixes may start with "*." (stripped to the same rule).
func hostMatches(host string, suffixes []string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	for _, s := range suffixes {
		s = normalizeHost(s)
		s = strings.TrimPrefix(s, "*.")
		if s == "" {
			continue
		}
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	// Bracketed IPv6 without port.
	host = strings.Trim(host, "[]")
	return host
}

// requestHost returns the best-effort host for matching (URL host, then Host header).
func requestHost(req *http.Request) string {
	if req == nil {
		return ""
	}
	if req.URL != nil && req.URL.Host != "" {
		return req.URL.Host
	}
	return req.Host
}

// pathLower returns the request path in lowercase (empty if unavailable).
func pathLower(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	return strings.ToLower(req.URL.Path)
}

// isMultipart reports whether Content-Type is multipart/form-data.
func isMultipart(h http.Header) bool {
	if h == nil {
		return false
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		return false
	}
	mediatype, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return strings.Contains(strings.ToLower(ct), "multipart/form-data")
	}
	return strings.EqualFold(mediatype, "multipart/form-data")
}

// contentDispositionFilename extracts filename= from Content-Disposition (if any).
func contentDispositionFilename(h http.Header) string {
	if h == nil {
		return ""
	}
	cd := h.Get("Content-Disposition")
	if cd == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		// Best-effort: filename="..."
		lower := strings.ToLower(cd)
		const key = "filename="
		if i := strings.Index(lower, key); i >= 0 {
			rest := cd[i+len(key):]
			rest = strings.Trim(rest, `"' `)
			if j := strings.IndexAny(rest, `";`); j >= 0 {
				rest = rest[:j]
			}
			return rest
		}
		return ""
	}
	if fn, ok := params["filename"]; ok {
		return fn
	}
	if fn, ok := params["filename*"]; ok {
		// RFC 5987: charset'lang'value — take value part if present.
		if parts := strings.SplitN(fn, "'", 3); len(parts) == 3 {
			return parts[2]
		}
		return fn
	}
	return ""
}

// isAttachment reports Content-Disposition attachment (download).
func isAttachment(h http.Header) bool {
	if h == nil {
		return false
	}
	cd := h.Get("Content-Disposition")
	if cd == "" {
		return false
	}
	mediatype, _, err := mime.ParseMediaType(cd)
	if err != nil {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(cd)), "attachment")
	}
	return strings.EqualFold(mediatype, "attachment")
}

// mediaTypeBase returns the base media type from Content-Type (lowercase), or "".
func mediaTypeBase(h http.Header) string {
	if h == nil {
		return ""
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		return ""
	}
	mediatype, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	}
	return strings.ToLower(mediatype)
}

// extensionOf returns the lowercase extension including dot (e.g. ".pdf"), or "".
func extensionOf(filename string) string {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return ""
	}
	// Strip path components if a full path sneaks in.
	base := path.Base(filename)
	ext := path.Ext(base)
	return strings.ToLower(ext)
}

// typeFilterAllows reports whether MIME/extension filters permit this traffic.
// Empty filters = allow all (still subject to action match).
// When filters are set, at least one MIME or extension must match (OR within each list;
// if both lists non-empty, either list may match).
func typeFilterAllows(mimeTypes, extensions []string, contentType, filename string) bool {
	if len(mimeTypes) == 0 && len(extensions) == 0 {
		return true
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	ext := extensionOf(filename)

	if len(mimeTypes) > 0 && ct != "" {
		for _, m := range mimeTypes {
			m = strings.ToLower(strings.TrimSpace(m))
			if m == "" {
				continue
			}
			if ct == m {
				return true
			}
			// Allow "image/*" style prefixes.
			if strings.HasSuffix(m, "/*") {
				prefix := strings.TrimSuffix(m, "*")
				if strings.HasPrefix(ct, prefix) {
					return true
				}
			}
		}
	}
	if len(extensions) > 0 && ext != "" {
		for _, e := range extensions {
			e = strings.ToLower(strings.TrimSpace(e))
			if e == "" {
				continue
			}
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			if ext == e {
				return true
			}
		}
	}
	// Filters configured but nothing matched → do not apply this restriction.
	return false
}

// pathContainsAny reports whether p contains any of the substrings (all already lowercased ideally).
func pathContainsAny(p string, needles ...string) bool {
	p = strings.ToLower(p)
	for _, n := range needles {
		if n != "" && strings.Contains(p, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// methodIs reports case-insensitive method equality.
func methodIs(req *http.Request, methods ...string) bool {
	if req == nil {
		return false
	}
	m := strings.ToUpper(req.Method)
	for _, want := range methods {
		if m == strings.ToUpper(want) {
			return true
		}
	}
	return false
}
