package casb

import (
	"context"
	"net/http"
	"strings"

	"github.com/wsp-security/wsp/internal/policy"
)

// ChatGPT detector — solid v1 coverage for file upload / attach and selected send endpoints.
// Hosts: chat.openai.com, chatgpt.com (plus backend API hosts used by the product).
type ChatGPT struct{}

// App implements Detector.
func (ChatGPT) App() string { return "chatgpt" }

// HostSuffixes implements Detector.
func (ChatGPT) HostSuffixes() []string {
	return []string{
		"chat.openai.com",
		"chatgpt.com",
		// File/CDN helpers sometimes used by ChatGPT web.
		"cdn.oaistatic.com",
	}
}

// Coverage implements Detector.
func (ChatGPT) Coverage() string {
	return "full: block_upload (multipart + /backend-api/files* endpoints); " +
		"block_send (conversation POST); block_download (attachment responses / file content GETs)"
}

// InspectRequest implements Detector.
func (d ChatGPT) InspectRequest(_ context.Context, req *http.Request, r policy.CASBRestriction) *Hit {
	if !appMatch(r.App, d.App()) && strings.TrimSpace(r.App) != "" {
		return nil
	}
	p := pathLower(req)

	// --- block_upload ---
	if restrictionHas(r, ActionBlockUpload) {
		if d.isUpload(req, p) {
			ct := mediaTypeBase(req.Header)
			fn := contentDispositionFilename(req.Header)
			if typeFilterAllows(r.MIMETypes, r.Extensions, ct, fn) {
				return &Hit{
					App:     d.App(),
					Action:  ActionBlockUpload,
					Message: FormatMessage(d.App(), ActionBlockUpload, "file attach / upload endpoint"),
				}
			}
		}
	}

	// --- block_send ---
	if restrictionHas(r, ActionBlockSend) {
		if d.isSend(req, p) {
			return &Hit{
				App:     d.App(),
				Action:  ActionBlockSend,
				Message: FormatMessage(d.App(), ActionBlockSend, "conversation endpoint"),
			}
		}
	}

	return nil
}

// InspectResponse implements Detector.
func (d ChatGPT) InspectResponse(_ context.Context, req *http.Request, resp *http.Response, r policy.CASBRestriction) *Hit {
	if !appMatch(r.App, d.App()) && strings.TrimSpace(r.App) != "" {
		return nil
	}
	if !restrictionHas(r, ActionBlockDownload) {
		return nil
	}
	if resp == nil {
		return nil
	}
	p := pathLower(req)
	// Attachment downloads or known file content paths.
	if isAttachment(resp.Header) || d.isFileContentPath(p) {
		ct := mediaTypeBase(resp.Header)
		fn := contentDispositionFilename(resp.Header)
		if typeFilterAllows(r.MIMETypes, r.Extensions, ct, fn) {
			return &Hit{
				App:     d.App(),
				Action:  ActionBlockDownload,
				Message: FormatMessage(d.App(), ActionBlockDownload, "file content response"),
			}
		}
	}
	return nil
}

func (ChatGPT) isUpload(req *http.Request, p string) bool {
	if !methodIs(req, http.MethodPost, http.MethodPut, http.MethodPatch) {
		return false
	}
	// Known ChatGPT / OpenAI web file endpoints.
	if pathContainsAny(p,
		"/backend-api/files",
		"/backend-api/conversation/", // sometimes carries attachments via related calls
		"/backend-api/attachments",
		"/backend-api/files/upload",
		"/backend-api/files/process",
		"/v1/files",
	) {
		// Narrow conversation path: only treat as upload when multipart.
		if strings.Contains(p, "/backend-api/conversation") {
			return isMultipart(req.Header)
		}
		return true
	}
	// Generic multipart POST to chatgpt hosts is treated as potential file attach.
	if isMultipart(req.Header) {
		return true
	}
	return false
}

func (ChatGPT) isSend(req *http.Request, p string) bool {
	if !methodIs(req, http.MethodPost) {
		return false
	}
	// Conversation create / continue (JSON body); exclude pure file endpoints.
	if strings.Contains(p, "/backend-api/files") {
		return false
	}
	return pathContainsAny(p,
		"/backend-api/conversation",
		"/backend-api/f/conversation",
		"/backend-api/lat/r",
	)
}

func (ChatGPT) isFileContentPath(p string) bool {
	return pathContainsAny(p,
		"/backend-api/files/",
		"/backend-api/project_files/",
		"/download/",
	)
}
