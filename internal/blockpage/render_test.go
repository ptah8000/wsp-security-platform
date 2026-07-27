package blockpage

import (
	"strings"
	"testing"
	"time"
)

func TestRenderEscapesAndSubstitutes(t *testing.T) {
	html := `<p>{{REASON}}</p><a>{{URL}}</a><span>{{USERNAME}}</span>`
	out := string(Render(html, Context{
		URL:      `https://x.test/<script>`,
		Reason:   `blocked & denied`,
		Username: `al<ice>`,
		Timestamp: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
	}))
	if strings.Contains(out, "<script>") {
		t.Fatalf("URL not escaped: %s", out)
	}
	if !strings.Contains(out, "blocked &amp; denied") {
		t.Fatalf("reason not escaped: %s", out)
	}
	if !strings.Contains(out, "al&lt;ice&gt;") {
		t.Fatalf("username not escaped: %s", out)
	}
}

func TestRenderDefaultTemplate(t *testing.T) {
	out := string(Render("", Context{Reason: "nope", URL: "https://example.com"}))
	if !strings.Contains(out, "Access blocked") {
		t.Fatalf("missing title: %s", out)
	}
	if !strings.Contains(out, "nope") {
		t.Fatalf("missing reason: %s", out)
	}
}

func TestShortBody(t *testing.T) {
	if string(ShortBody("")) != "Blocked by policy\n" {
		t.Fatalf("default short body unexpected")
	}
}
