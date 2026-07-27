package casb

import (
	"context"
	"net/http"
	"strings"

	"github.com/wsp-security/wsp/internal/policy"
)

// Slack detector — partial v1 coverage (host list + path heuristics).
// Full message-post and all edge upload APIs are not exhaustively covered.
type Slack struct{}

// App implements Detector.
func (Slack) App() string { return "slack" }

// HostSuffixes implements Detector.
func (Slack) HostSuffixes() []string {
	return []string{
		"app.slack.com",
		"files.slack.com",
		"files-origin.slack.com",
		"upload.slack.com",
		"slack.com",
		"slack-edge.com",
		"slack-files.com",
	}
}

// Coverage implements Detector.
func (Slack) Coverage() string {
	return "partial: host patterns for app.slack.com / files.slack.com; " +
		"block_upload on files.slack.com + multipart /files.uploads paths; " +
		"block_download on files.slack.com GETs and Content-Disposition attachment; " +
		"block_message best-effort on chat.postMessage / conversations.history POST only — " +
		"not all client websocket/message edge cases"
}

// InspectRequest implements Detector.
func (d Slack) InspectRequest(_ context.Context, req *http.Request, r policy.CASBRestriction) *Hit {
	if !appMatch(r.App, d.App()) && strings.TrimSpace(r.App) != "" {
		return nil
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
				Message: FormatMessage(d.App(), ActionBlockUpload, "partial: upload path"),
			}
		}
	}

	if restrictionHas(r, ActionBlockMessage) && d.isMessagePost(req, p) {
		return &Hit{
			App:     d.App(),
			Action:  ActionBlockMessage,
			Message: FormatMessage(d.App(), ActionBlockMessage, "partial: chat API"),
		}
	}

	if restrictionHas(r, ActionBlockDownload) && d.isDownloadRequest(req, p, host) {
		return &Hit{
			App:     d.App(),
			Action:  ActionBlockDownload,
			Message: FormatMessage(d.App(), ActionBlockDownload, "partial: files host GET"),
		}
	}

	return nil
}

// InspectResponse implements Detector.
func (d Slack) InspectResponse(_ context.Context, req *http.Request, resp *http.Response, r policy.CASBRestriction) *Hit {
	if !appMatch(r.App, d.App()) && strings.TrimSpace(r.App) != "" {
		return nil
	}
	if !restrictionHas(r, ActionBlockDownload) || resp == nil {
		return nil
	}
	host := normalizeHost(requestHost(req))
	if isAttachment(resp.Header) || strings.Contains(host, "files.slack") || strings.Contains(host, "slack-files") {
		ct := mediaTypeBase(resp.Header)
		if isBrowserShell(ct) && !isAttachment(resp.Header) {
			return nil
		}
		fn := contentDispositionFilename(resp.Header)
		if typeFilterAllows(r.MIMETypes, r.Extensions, ct, fn) {
			return &Hit{
				App:     d.App(),
				Action:  ActionBlockDownload,
				Message: FormatMessage(d.App(), ActionBlockDownload, "partial: file response"),
			}
		}
	}
	return nil
}

func (Slack) isUpload(req *http.Request, p, host string) bool {
	if !methodIs(req, http.MethodPost, http.MethodPut) {
		return false
	}
	if pathContainsAny(p, "/files.upload", "/files.completeupload", "/api/files.", "/upload") {
		return true
	}
	if isMultipart(req.Header) && (strings.Contains(host, "slack") || pathContainsAny(p, "/files")) {
		return true
	}
	if strings.Contains(host, "upload.slack") || strings.Contains(host, "files.slack") {
		return methodIs(req, http.MethodPost, http.MethodPut)
	}
	return false
}

func (Slack) isMessagePost(req *http.Request, p string) bool {
	if !methodIs(req, http.MethodPost) {
		return false
	}
	return pathContainsAny(p,
		"/api/chat.postmessage",
		"/api/chat.meMessage",
		"/api/chat.scheduleMessage",
		"/api/files.remote.add",
	) || strings.Contains(p, "chat.postmessage")
}

func (Slack) isDownloadRequest(req *http.Request, p, host string) bool {
	if !methodIs(req, http.MethodGet, http.MethodHead) {
		return false
	}
	if strings.Contains(host, "files.slack") || strings.Contains(host, "slack-files") {
		return true
	}
	return pathContainsAny(p, "/files-pri/", "/download/", "/file_download")
}
