package casb

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/wsp-security/wsp/internal/policy"
)

// GoogleDrive detector — solid v1 coverage for Drive/Docs upload and download patterns.
// Also covers common Google APIs used by Drive (googleapis upload,usercontent downloads).
type GoogleDrive struct{}

// App implements Detector.
func (GoogleDrive) App() string { return "google_drive" }

// HostSuffixes implements Detector.
func (GoogleDrive) HostSuffixes() []string {
	return []string{
		"drive.google.com",
		"docs.google.com",
		"drive.usercontent.google.com",
		"www.googleapis.com",
		"googleapis.com",
		"googleusercontent.com",
		// Clients used by Drive web UI for some transfer endpoints.
		"clients6.google.com",
		"upload.google.com",
	}
}

// Coverage implements Detector.
func (GoogleDrive) Coverage() string {
	return "full: block_upload (Drive/Docs upload + resumable/googleapis upload paths); " +
		"block_download (export/uc download URLs + Content-Disposition attachment)"
}

// InspectRequest implements Detector.
func (d GoogleDrive) InspectRequest(_ context.Context, req *http.Request, r policy.CASBRestriction) *Hit {
	if !appMatch(r.App, d.App()) && strings.TrimSpace(r.App) != "" {
		return nil
	}
	p := pathLower(req)
	q := ""
	if req.URL != nil {
		q = strings.ToLower(req.URL.RawQuery)
	}

	if restrictionHas(r, ActionBlockUpload) && d.isUpload(req, p, q) {
		ct := mediaTypeBase(req.Header)
		fn := contentDispositionFilename(req.Header)
		if typeFilterAllows(r.MIMETypes, r.Extensions, ct, fn) {
			return &Hit{
				App:     d.App(),
				Action:  ActionBlockUpload,
				Message: FormatMessage(d.App(), ActionBlockUpload, "upload endpoint"),
			}
		}
	}

	// Some downloads are initiated as GET with export/download query flags (request-side).
	if restrictionHas(r, ActionBlockDownload) && d.isDownloadRequest(req, p, q) {
		ct := mediaTypeBase(req.Header)
		fn := filenameFromQuery(req.URL)
		if typeFilterAllows(r.MIMETypes, r.Extensions, ct, fn) {
			return &Hit{
				App:     d.App(),
				Action:  ActionBlockDownload,
				Message: FormatMessage(d.App(), ActionBlockDownload, "download URL"),
			}
		}
	}

	return nil
}

// InspectResponse implements Detector.
func (d GoogleDrive) InspectResponse(_ context.Context, req *http.Request, resp *http.Response, r policy.CASBRestriction) *Hit {
	if !appMatch(r.App, d.App()) && strings.TrimSpace(r.App) != "" {
		return nil
	}
	if !restrictionHas(r, ActionBlockDownload) || resp == nil {
		return nil
	}
	p := pathLower(req)
	q := ""
	if req.URL != nil {
		q = strings.ToLower(req.URL.RawQuery)
	}

	// Attachment header is the strongest signal for downloads.
	if isAttachment(resp.Header) || d.isDownloadRequest(req, p, q) || d.isDownloadyContentType(resp.Header) {
		// Avoid blocking ordinary HTML/JSON app shells.
		ct := mediaTypeBase(resp.Header)
		if isBrowserShell(ct) && !isAttachment(resp.Header) {
			return nil
		}
		fn := contentDispositionFilename(resp.Header)
		if fn == "" {
			fn = filenameFromQuery(req.URL)
		}
		if typeFilterAllows(r.MIMETypes, r.Extensions, ct, fn) {
			return &Hit{
				App:     d.App(),
				Action:  ActionBlockDownload,
				Message: FormatMessage(d.App(), ActionBlockDownload, "file download response"),
			}
		}
	}
	return nil
}

func (GoogleDrive) isUpload(req *http.Request, p, q string) bool {
	if !methodIs(req, http.MethodPost, http.MethodPut, http.MethodPatch) {
		return false
	}
	// Google Drive / Docs upload API patterns.
	if pathContainsAny(p,
		"/upload/drive/",
		"/resumable/upload",
		"/upload/storage/",
		"/upload/",
	) {
		return true
	}
	// Drive web UI upload paths.
	if pathContainsAny(p,
		"/file/d/",
		"/drive/v3/files",
		"/drive/v2/files",
	) && (strings.Contains(q, "uploadtype=") || strings.Contains(q, "upload_id=") || isMultipart(req.Header)) {
		return true
	}
	// clients6 / drive batch upload markers.
	if pathContainsAny(p, "/upload/drive", "/_/upload", "/filemanager/") {
		return true
	}
	if isMultipart(req.Header) && pathContainsAny(p, "/drive", "/docs", "/file") {
		return true
	}
	// application/octet-stream POST often used by resumable chunk uploads.
	if methodIs(req, http.MethodPut, http.MethodPost) {
		ct := mediaTypeBase(req.Header)
		if ct == "application/octet-stream" && pathContainsAny(p, "upload", "resumable") {
			return true
		}
	}
	return false
}

func (GoogleDrive) isDownloadRequest(req *http.Request, p, q string) bool {
	if !methodIs(req, http.MethodGet, http.MethodHead, http.MethodPost) {
		return false
	}
	// Classic Drive download endpoints.
	if pathContainsAny(p, "/uc") && (strings.Contains(q, "export=download") || strings.Contains(q, "confirm=")) {
		return true
	}
	if strings.Contains(q, "export=download") || strings.Contains(q, "exportformat=") {
		return true
	}
	if pathContainsAny(p,
		"/export",
		"/uc",
		"/download",
		"/file/d/",
	) && (strings.Contains(q, "export") || strings.Contains(q, "download") || strings.Contains(p, "/export")) {
		return true
	}
	// googleapis media download: alt=media
	if strings.Contains(q, "alt=media") && pathContainsAny(p, "/drive/", "/files/") {
		return true
	}
	// usercontent direct content hosts often use /download or bare content paths.
	host := normalizeHost(requestHost(req))
	if strings.Contains(host, "usercontent") && methodIs(req, http.MethodGet) {
		if pathContainsAny(p, "/download", "/d/") || strings.Contains(q, "export") {
			return true
		}
	}
	return false
}

func (GoogleDrive) isDownloadyContentType(h http.Header) bool {
	ct := mediaTypeBase(h)
	switch {
	case ct == "":
		return false
	case strings.HasPrefix(ct, "application/octet-stream"):
		return true
	case strings.HasPrefix(ct, "application/zip"):
		return true
	case strings.HasPrefix(ct, "application/pdf"):
		return true
	case strings.HasPrefix(ct, "application/vnd."):
		// Office / Google MIME types
		return true
	default:
		return false
	}
}

func isBrowserShell(ct string) bool {
	switch ct {
	case "text/html", "application/json", "text/javascript", "application/javascript", "text/css", "image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml":
		return true
	default:
		return false
	}
}

func filenameFromQuery(u *url.URL) string {
	if u == nil {
		return ""
	}
	q := u.Query()
	for _, key := range []string{"filename", "fileName", "title", "name"} {
		if v := q.Get(key); v != "" {
			return v
		}
	}
	return ""
}
