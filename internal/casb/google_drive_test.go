package casb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wsp-security/wsp/internal/policy"
)

func TestGoogleDrive_BlockUpload_APIPath(t *testing.T) {
	d := GoogleDrive{}
	req := httptest.NewRequest(http.MethodPost, "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart", nil)
	req.Header.Set("Content-Type", "multipart/related; boundary=foo")
	r := policy.CASBRestriction{App: "google_drive", Actions: []string{ActionBlockUpload}}

	hit := d.InspectRequest(context.Background(), req, r)
	if hit == nil {
		t.Fatal("expected Hit for googleapis upload path")
	}
	if hit.App != "google_drive" || hit.Action != ActionBlockUpload {
		t.Fatalf("hit = %+v", hit)
	}
	if !strings.Contains(hit.Message, "Google Drive") {
		t.Fatalf("targeted message expected: %q", hit.Message)
	}
}

func TestGoogleDrive_BlockUpload_Resumable(t *testing.T) {
	d := GoogleDrive{}
	req := httptest.NewRequest(http.MethodPut, "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=abc", strings.NewReader("chunk"))
	req.Header.Set("Content-Type", "application/octet-stream")
	r := policy.CASBRestriction{App: "google_drive", Actions: []string{ActionBlockUpload}}

	if hit := d.InspectRequest(context.Background(), req, r); hit == nil {
		t.Fatal("expected Hit for resumable upload chunk")
	}
}

func TestGoogleDrive_BlockDownload_ExportURL(t *testing.T) {
	d := GoogleDrive{}
	req := httptest.NewRequest(http.MethodGet, "https://drive.google.com/uc?export=download&id=FILEID", nil)
	r := policy.CASBRestriction{App: "google_drive", Actions: []string{ActionBlockDownload}}

	hit := d.InspectRequest(context.Background(), req, r)
	if hit == nil {
		t.Fatal("expected Hit for export=download URL")
	}
	if hit.Action != ActionBlockDownload {
		t.Fatalf("action = %s", hit.Action)
	}
}

func TestGoogleDrive_BlockDownload_ContentDisposition(t *testing.T) {
	d := GoogleDrive{}
	req := httptest.NewRequest(http.MethodGet, "https://drive.google.com/file/d/abc/view", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Request:    req,
	}
	resp.Header.Set("Content-Disposition", `attachment; filename="report.xlsx"`)
	resp.Header.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	r := policy.CASBRestriction{App: "google_drive", Actions: []string{ActionBlockDownload}}

	hit := d.InspectResponse(context.Background(), req, resp, r)
	if hit == nil {
		t.Fatal("expected Hit for Content-Disposition attachment")
	}
	if hit.Action != ActionBlockDownload {
		t.Fatalf("action = %s", hit.Action)
	}
}

func TestGoogleDrive_BlockDownload_AltMedia(t *testing.T) {
	d := GoogleDrive{}
	req := httptest.NewRequest(http.MethodGet, "https://www.googleapis.com/drive/v3/files/abc?alt=media", nil)
	r := policy.CASBRestriction{App: "google_drive", Actions: []string{ActionBlockDownload}}

	if hit := d.InspectRequest(context.Background(), req, r); hit == nil {
		t.Fatal("expected Hit for alt=media download")
	}
}

func TestGoogleDrive_AllowBrowsingHTML(t *testing.T) {
	d := GoogleDrive{}
	req := httptest.NewRequest(http.MethodGet, "https://drive.google.com/drive/my-drive", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	r := policy.CASBRestriction{App: "google_drive", Actions: []string{ActionBlockDownload}}

	if hit := d.InspectResponse(context.Background(), req, resp, r); hit != nil {
		t.Fatalf("HTML shell must not be blocked as download: %+v", hit)
	}
}

func TestGoogleDrive_ExtensionFilter(t *testing.T) {
	d := GoogleDrive{}
	req := httptest.NewRequest(http.MethodGet, "https://drive.google.com/uc?export=download&id=x", nil)
	resp := &http.Response{StatusCode: 200, Header: make(http.Header), Request: req}
	resp.Header.Set("Content-Disposition", `attachment; filename="secret.docx"`)
	resp.Header.Set("Content-Type", "application/octet-stream")

	// Filter for .pdf only — docx should not match.
	r := policy.CASBRestriction{
		App:        "google_drive",
		Actions:    []string{ActionBlockDownload},
		Extensions: []string{".pdf"},
	}
	if hit := d.InspectResponse(context.Background(), req, resp, r); hit != nil {
		t.Fatalf("unexpected hit for non-matching extension: %+v", hit)
	}

	r.Extensions = []string{"docx"}
	if hit := d.InspectResponse(context.Background(), req, resp, r); hit == nil {
		t.Fatal("expected hit when extension filter matches docx")
	}
}

func TestGoogleDrive_NoAction_NoHit(t *testing.T) {
	d := GoogleDrive{}
	req := httptest.NewRequest(http.MethodPost, "https://www.googleapis.com/upload/drive/v3/files", nil)
	r := policy.CASBRestriction{App: "google_drive", Actions: []string{ActionBlockDownload}}
	if hit := d.InspectRequest(context.Background(), req, r); hit != nil {
		t.Fatalf("upload must not fire on block_download-only: %+v", hit)
	}
}

func TestInspector_GoogleDrive_AndChatGPT_Isolation(t *testing.T) {
	in := Default()
	req := httptest.NewRequest(http.MethodPost, "https://www.googleapis.com/upload/drive/v3/files", nil)
	// Restriction for chatgpt should not fire on Drive host.
	hit := in.InspectRequest(context.Background(), req, []policy.CASBRestriction{
		{App: "chatgpt", Actions: []string{ActionBlockUpload}},
	})
	if hit != nil {
		t.Fatalf("chatgpt restriction must not apply to drive host: %+v", hit)
	}
	hit = in.InspectRequest(context.Background(), req, []policy.CASBRestriction{
		{App: "google_drive", Actions: []string{ActionBlockUpload}},
	})
	if hit == nil {
		t.Fatal("expected google_drive hit")
	}
}

func TestGoogleDrive_Coverage(t *testing.T) {
	c := GoogleDrive{}.Coverage()
	if !strings.Contains(c, "full") {
		t.Fatalf("coverage should document full depth: %q", c)
	}
}

func TestPartialDetectors_CoverageDocumented(t *testing.T) {
	for _, d := range []Detector{Slack{}, M365{}, WhatsApp{}} {
		c := d.Coverage()
		if !strings.Contains(strings.ToLower(c), "partial") {
			t.Errorf("%s Coverage() should mention partial: %q", d.App(), c)
		}
	}
}

func TestDefaultCatalog_RegistersFiveApps(t *testing.T) {
	in := Default()
	apps := map[string]bool{}
	for _, d := range in.Detectors() {
		apps[d.App()] = true
	}
	for _, want := range []string{"chatgpt", "google_drive", "slack", "m365", "whatsapp_web"} {
		if !apps[want] {
			t.Errorf("missing detector %s", want)
		}
	}
}

func TestHostMatches_SuffixAndPort(t *testing.T) {
	suffixes := []string{"drive.google.com", "*.sharepoint.com"}
	if !hostMatches("drive.google.com:443", suffixes) {
		t.Fatal("expected port strip match")
	}
	if !hostMatches("contoso.sharepoint.com", suffixes) {
		t.Fatal("expected wildcard suffix match")
	}
	if hostMatches("evilsharepoint.com", suffixes) {
		t.Fatal("must not match lookalike domain")
	}
}
