package casb

import (
	"context"
	"net/http"
	"strings"

	"github.com/wsp-security/wsp/internal/policy"
)

// WhatsApp detector — partial / best-effort for WhatsApp Web.
// Media often uses CDN hosts and encrypted blobs; detection is intentionally limited.
type WhatsApp struct{}

// App implements Detector.
func (WhatsApp) App() string { return "whatsapp_web" }

// HostSuffixes implements Detector.
func (WhatsApp) HostSuffixes() []string {
	return []string{
		"web.whatsapp.com",
		"whatsapp.com",
		"whatsapp.net",
		"mmg.whatsapp.net",
		"pps.whatsapp.net",
		"media.whatsapp.com",
	}
}

// Coverage implements Detector.
func (WhatsApp) Coverage() string {
	return "partial/best-effort: web.whatsapp.com host; " +
		"block_upload on multipart POSTs and media upload path fragments; " +
		"block_download on mmg/pps media GETs and Content-Disposition attachment; " +
		"E2E media encryption and dynamic CDN hostnames limit reliability — document detection limits"
}

// InspectRequest implements Detector.
func (d WhatsApp) InspectRequest(_ context.Context, req *http.Request, r policy.CASBRestriction) *Hit {
	if !appMatch(r.App, d.App()) && strings.TrimSpace(r.App) != "" {
		// Accept legacy alias "whatsapp".
		if !strings.EqualFold(strings.TrimSpace(r.App), "whatsapp") {
			return nil
		}
	}
	p := pathLower(req)
	host := normalizeHost(requestHost(req))

	if restrictionHas(r, ActionBlockUpload) && d.isUpload(req, p, host) {
		ct := mediaTypeBase(req.Header)
		fn := contentDispositionFilename(req.Header)
		if typeFilterAllows(r.MIMETypes, r.Extensions, ct, fn) {
			return &Hit{
				App:     d.App(),
				Action:  ActionBlockUpload,
				Message: FormatMessage(d.App(), ActionBlockUpload, "partial: media upload"),
			}
		}
	}

	if restrictionHas(r, ActionBlockDownload) && d.isDownloadRequest(req, p, host) {
		return &Hit{
			App:     d.App(),
			Action:  ActionBlockDownload,
			Message: FormatMessage(d.App(), ActionBlockDownload, "partial: media GET"),
		}
	}

	return nil
}

// InspectResponse implements Detector.
func (d WhatsApp) InspectResponse(_ context.Context, req *http.Request, resp *http.Response, r policy.CASBRestriction) *Hit {
	if !appMatch(r.App, d.App()) && strings.TrimSpace(r.App) != "" {
		if !strings.EqualFold(strings.TrimSpace(r.App), "whatsapp") {
			return nil
		}
	}
	if !restrictionHas(r, ActionBlockDownload) || resp == nil {
		return nil
	}
	host := normalizeHost(requestHost(req))
	if isAttachment(resp.Header) || d.isMediaHost(host) {
		ct := mediaTypeBase(resp.Header)
		if isBrowserShell(ct) && !isAttachment(resp.Header) {
			return nil
		}
		fn := contentDispositionFilename(resp.Header)
		if typeFilterAllows(r.MIMETypes, r.Extensions, ct, fn) {
			return &Hit{
				App:     d.App(),
				Action:  ActionBlockDownload,
				Message: FormatMessage(d.App(), ActionBlockDownload, "partial: media response"),
			}
		}
	}
	return nil
}

func (d WhatsApp) isUpload(req *http.Request, p, host string) bool {
	if !methodIs(req, http.MethodPost, http.MethodPut) {
		return false
	}
	if isMultipart(req.Header) {
		return true
	}
	if pathContainsAny(p, "/upload", "/media", "/mms", "/enc") {
		return true
	}
	if d.isMediaHost(host) && methodIs(req, http.MethodPost, http.MethodPut) {
		return true
	}
	return false
}

func (d WhatsApp) isDownloadRequest(req *http.Request, p, host string) bool {
	if !methodIs(req, http.MethodGet, http.MethodHead) {
		return false
	}
	if d.isMediaHost(host) {
		return true
	}
	return pathContainsAny(p, "/download", "/media", "/mms")
}

func (WhatsApp) isMediaHost(host string) bool {
	return strings.Contains(host, "mmg.whatsapp") ||
		strings.Contains(host, "pps.whatsapp") ||
		strings.Contains(host, "media.whatsapp") ||
		strings.HasSuffix(host, "whatsapp.net")
}
