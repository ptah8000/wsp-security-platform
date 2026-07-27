package casb

import (
	"context"
	"net/http"
	"strings"

	"github.com/wsp-security/wsp/internal/policy"
)

// M365 detector — partial v1 coverage for Outlook Web / OneDrive / SharePoint hosts.
type M365 struct{}

// App implements Detector.
func (M365) App() string { return "m365" }

// HostSuffixes implements Detector.
func (M365) HostSuffixes() []string {
	return []string{
		"outlook.office.com",
		"outlook.office365.com",
		"outlook.live.com",
		"onedrive.live.com",
		"sharepoint.com",
		"sharepointonline.com",
		"1drv.ms",
		"office.com",
		"officeapps.live.com",
		"graph.microsoft.com",
	}
}

// Coverage implements Detector.
func (M365) Coverage() string {
	return "partial: host patterns for OWA/OneDrive/SharePoint/Graph; " +
		"block_upload on createUploadSession / resumable / multipart paths; " +
		"block_download on download.aspx, /_layouts/15/download.aspx, alt=media, attachment CD; " +
		"not full Graph surface or desktop sync protocol coverage"
}

// InspectRequest implements Detector.
func (d M365) InspectRequest(_ context.Context, req *http.Request, r policy.CASBRestriction) *Hit {
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
				Message: FormatMessage(d.App(), ActionBlockUpload, "partial: upload path"),
			}
		}
	}

	if restrictionHas(r, ActionBlockDownload) && d.isDownloadRequest(req, p, q) {
		return &Hit{
			App:     d.App(),
			Action:  ActionBlockDownload,
			Message: FormatMessage(d.App(), ActionBlockDownload, "partial: download URL"),
		}
	}

	return nil
}

// InspectResponse implements Detector.
func (d M365) InspectResponse(_ context.Context, req *http.Request, resp *http.Response, r policy.CASBRestriction) *Hit {
	if !appMatch(r.App, d.App()) && strings.TrimSpace(r.App) != "" {
		return nil
	}
	if !restrictionHas(r, ActionBlockDownload) || resp == nil {
		return nil
	}
	if isAttachment(resp.Header) {
		ct := mediaTypeBase(resp.Header)
		fn := contentDispositionFilename(resp.Header)
		if typeFilterAllows(r.MIMETypes, r.Extensions, ct, fn) {
			return &Hit{
				App:     d.App(),
				Action:  ActionBlockDownload,
				Message: FormatMessage(d.App(), ActionBlockDownload, "partial: attachment response"),
			}
		}
	}
	return nil
}

func (M365) isUpload(req *http.Request, p, q string) bool {
	if !methodIs(req, http.MethodPost, http.MethodPut, http.MethodPatch) {
		return false
	}
	if pathContainsAny(p,
		"createuploadsession",
		"/uploadsession",
		"/_api/web/",
		"/_vti_bin/",
		"/upload",
		"/attachments/",
	) {
		return true
	}
	if strings.Contains(q, "uploadsession") || strings.Contains(q, "@microsoft.graph.upload") {
		return true
	}
	if isMultipart(req.Header) {
		return true
	}
	// Graph content upload: ...:/content
	if strings.HasSuffix(p, ":/content") || strings.Contains(p, ":/content") {
		return true
	}
	return false
}

func (M365) isDownloadRequest(req *http.Request, p, q string) bool {
	if !methodIs(req, http.MethodGet, http.MethodHead) {
		return false
	}
	if pathContainsAny(p,
		"download.aspx",
		"/_layouts/",
		"/downloadbypath",
		"/download.aspx",
	) {
		return true
	}
	if strings.Contains(q, "download=1") || strings.Contains(q, "alt=media") {
		return true
	}
	if strings.Contains(p, "/attachments/") && methodIs(req, http.MethodGet) {
		return true
	}
	return false
}
