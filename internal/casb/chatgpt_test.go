package casb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wsp-security/wsp/internal/policy"
)

func TestChatGPT_BlockUpload_Multipart(t *testing.T) {
	d := ChatGPT{}
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/conversation", strings.NewReader("--boundary"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r := policy.CASBRestriction{App: "chatgpt", Actions: []string{ActionBlockUpload}}

	hit := d.InspectRequest(context.Background(), req, r)
	if hit == nil {
		t.Fatal("expected Hit for multipart upload")
	}
	if hit.App != "chatgpt" || hit.Action != ActionBlockUpload {
		t.Fatalf("hit = %+v", hit)
	}
	if !strings.Contains(hit.Message, "CASB") || !strings.Contains(hit.Message, "ChatGPT") {
		t.Fatalf("message should be targeted: %q", hit.Message)
	}
}

func TestChatGPT_BlockUpload_FilesEndpoint(t *testing.T) {
	d := ChatGPT{}
	req := httptest.NewRequest(http.MethodPost, "https://chat.openai.com/backend-api/files", nil)
	req.Header.Set("Content-Type", "application/json")
	r := policy.CASBRestriction{App: "chatgpt", Actions: []string{ActionBlockUpload}}

	hit := d.InspectRequest(context.Background(), req, r)
	if hit == nil {
		t.Fatal("expected Hit for /backend-api/files")
	}
	if hit.Action != ActionBlockUpload {
		t.Fatalf("action = %s", hit.Action)
	}
}

func TestChatGPT_AllowWhenNoUploadAction(t *testing.T) {
	d := ChatGPT{}
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/files", nil)
	r := policy.CASBRestriction{App: "chatgpt", Actions: []string{ActionBlockDownload}}

	if hit := d.InspectRequest(context.Background(), req, r); hit != nil {
		t.Fatalf("unexpected hit: %+v", hit)
	}
}

func TestChatGPT_BlockSend_Conversation(t *testing.T) {
	d := ChatGPT{}
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/conversation", strings.NewReader(`{"messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	r := policy.CASBRestriction{App: "chatgpt", Actions: []string{ActionBlockSend}}

	hit := d.InspectRequest(context.Background(), req, r)
	if hit == nil {
		t.Fatal("expected Hit for conversation send")
	}
	if hit.Action != ActionBlockSend {
		t.Fatalf("action = %s", hit.Action)
	}
}

func TestChatGPT_BlockDownload_Attachment(t *testing.T) {
	d := ChatGPT{}
	req := httptest.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/files/file-abc/download", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Request:    req,
	}
	resp.Header.Set("Content-Disposition", `attachment; filename="notes.pdf"`)
	resp.Header.Set("Content-Type", "application/pdf")
	r := policy.CASBRestriction{App: "chatgpt", Actions: []string{ActionBlockDownload}}

	hit := d.InspectResponse(context.Background(), req, resp, r)
	if hit == nil {
		t.Fatal("expected Hit for download attachment")
	}
	if hit.Action != ActionBlockDownload {
		t.Fatalf("action = %s", hit.Action)
	}
}

func TestChatGPT_MIMEFilter_SkipsNonMatching(t *testing.T) {
	d := ChatGPT{}
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/files", nil)
	req.Header.Set("Content-Type", "image/png")
	r := policy.CASBRestriction{
		App:       "chatgpt",
		Actions:   []string{ActionBlockUpload},
		MIMETypes: []string{"application/pdf"},
	}
	if hit := d.InspectRequest(context.Background(), req, r); hit != nil {
		t.Fatalf("expected no hit when MIME filter excludes content-type, got %+v", hit)
	}
}

func TestChatGPT_MIMEFilter_Matches(t *testing.T) {
	d := ChatGPT{}
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/files", nil)
	req.Header.Set("Content-Type", "application/pdf")
	r := policy.CASBRestriction{
		App:       "chatgpt",
		Actions:   []string{ActionBlockUpload},
		MIMETypes: []string{"application/pdf"},
	}
	if hit := d.InspectRequest(context.Background(), req, r); hit == nil {
		t.Fatal("expected hit when MIME filter matches")
	}
}

func TestInspector_ChatGPT_HostRouting(t *testing.T) {
	in := Default()
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/files", nil)
	restrictions := []policy.CASBRestriction{
		{App: "chatgpt", Actions: []string{ActionBlockUpload}},
	}
	hit := in.InspectRequest(context.Background(), req, restrictions)
	if hit == nil {
		t.Fatal("expected catalog hit")
	}

	// Wrong host should not hit even with chatgpt restriction.
	req2 := httptest.NewRequest(http.MethodPost, "https://example.com/backend-api/files", nil)
	if hit := in.InspectRequest(context.Background(), req2, restrictions); hit != nil {
		t.Fatalf("unexpected hit on non-chatgpt host: %+v", hit)
	}
}

func TestProxyAdapter_EmptyCASB_Noop(t *testing.T) {
	a := NewProxyAdapter()
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/files", nil)
	reason, err := a.InspectRequest(context.Background(), req, policy.Decision{})
	if err != nil {
		t.Fatal(err)
	}
	if reason != "" {
		t.Fatalf("expected empty reason without CASB restrictions, got %q", reason)
	}
}

func TestProxyAdapter_BlocksWithReason(t *testing.T) {
	a := NewProxyAdapter()
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/files", nil)
	d := policy.Decision{
		CASB: []policy.CASBRestriction{{App: "chatgpt", Actions: []string{ActionBlockUpload}}},
	}
	reason, err := a.InspectRequest(context.Background(), req, d)
	if err != nil {
		t.Fatal(err)
	}
	if reason == "" || !strings.Contains(reason, "ChatGPT") {
		t.Fatalf("expected targeted CASB reason, got %q", reason)
	}
}

func TestChatGPT_Coverage(t *testing.T) {
	c := ChatGPT{}.Coverage()
	if !strings.Contains(c, "full") {
		t.Fatalf("coverage should document full depth: %q", c)
	}
}
