// Package blockpage renders policy block HTML for denied proxy requests.
package blockpage

import (
	"html"
	"strings"
	"time"
)

// DefaultSystemBlockPageID is the UUID of the seed system block page in migrations.
const DefaultSystemBlockPageID = "00000000-0000-4000-8000-000000000001"

// Context holds values substituted into block page templates.
type Context struct {
	URL       string
	Reason    string
	Username  string
	ClientIP  string
	RuleID    string
	Timestamp time.Time
}

// DefaultHTML is the built-in block page used when no custom HTML is available.
func DefaultHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Access Blocked</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
           display: grid; place-items: center; min-height: 100vh; margin: 0; }
    main { max-width: 32rem; padding: 2rem; border: 1px solid #334155; border-radius: 0.75rem;
           background: #1e293b; text-align: center; }
    h1 { margin: 0 0 0.75rem; font-size: 1.5rem; }
    p { margin: 0; color: #94a3b8; line-height: 1.5; }
    .meta { margin-top: 1rem; font-size: 0.875rem; word-break: break-all; }
  </style>
</head>
<body>
  <main>
    <h1>Access blocked</h1>
    <p>This request was blocked by your organization&rsquo;s web security policy.</p>
    <p class="meta">{{REASON}}</p>
    <p class="meta">{{URL}}</p>
    <p class="meta">{{TIMESTAMP}}</p>
  </main>
</body>
</html>`
}

// Render substitutes known placeholders in htmlTemplate.
// Unknown placeholders are left as-is. Values are HTML-escaped.
//
// Placeholders: {{URL}} {{REASON}} {{USERNAME}} {{CLIENT_IP}} {{RULE_ID}} {{TIMESTAMP}}
func Render(htmlTemplate string, ctx Context) []byte {
	if htmlTemplate == "" {
		htmlTemplate = DefaultHTML()
	}
	ts := ctx.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	reason := ctx.Reason
	if reason == "" {
		reason = "Blocked by policy"
	}

	repl := map[string]string{
		"{{URL}}":       html.EscapeString(ctx.URL),
		"{{REASON}}":    html.EscapeString(reason),
		"{{USERNAME}}":  html.EscapeString(ctx.Username),
		"{{CLIENT_IP}}": html.EscapeString(ctx.ClientIP),
		"{{RULE_ID}}":   html.EscapeString(ctx.RuleID),
		"{{TIMESTAMP}}": html.EscapeString(ts.UTC().Format(time.RFC3339)),
	}

	out := htmlTemplate
	for k, v := range repl {
		out = strings.ReplaceAll(out, k, v)
	}
	return []byte(out)
}

// ShortBody is a plain-text body for CONNECT 403 responses when MITM is off.
func ShortBody(reason string) []byte {
	if reason == "" {
		reason = "Blocked by policy"
	}
	return []byte(reason + "\n")
}
