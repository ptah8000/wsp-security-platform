// Package casb implements inline Cloud Access Security Broker inspection.
// Detectors match decrypted HTTP traffic by host/path/method/headers (no SaaS APIs).
package casb

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/wsp-security/wsp/internal/policy"
)

// Supported CASB action identifiers (match seed reusable_objects / policy JSON).
const (
	ActionBlockUpload   = "block_upload"
	ActionBlockDownload = "block_download"
	ActionBlockSend     = "block_send"
	ActionBlockMessage  = "block_message"
)

// Hit is a CASB control that fired and should produce a targeted block page.
type Hit struct {
	App     string
	Action  string
	Message string
}

// FormatMessage builds a user-facing block reason for a Hit.
func FormatMessage(app, action, detail string) string {
	label := appLabel(app)
	act := actionLabel(action)
	if detail != "" {
		return fmt.Sprintf("CASB: %s — %s (%s)", label, act, detail)
	}
	return fmt.Sprintf("CASB: %s — %s blocked by policy", label, act)
}

func appLabel(app string) string {
	switch strings.ToLower(strings.TrimSpace(app)) {
	case "chatgpt":
		return "ChatGPT"
	case "google_drive":
		return "Google Drive"
	case "m365":
		return "Microsoft 365"
	case "slack":
		return "Slack"
	case "whatsapp_web", "whatsapp":
		return "WhatsApp Web"
	default:
		if app == "" {
			return "Cloud app"
		}
		return app
	}
}

func actionLabel(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case ActionBlockUpload:
		return "file upload"
	case ActionBlockDownload:
		return "file download"
	case ActionBlockSend:
		return "send"
	case ActionBlockMessage:
		return "message post"
	default:
		if action == "" {
			return "action"
		}
		return action
	}
}

// Detector inspects traffic for one cloud application.
type Detector interface {
	// App returns the stable app id (e.g. "chatgpt", "google_drive").
	App() string
	// HostSuffixes returns host suffixes this detector claims (lowercase, no port).
	HostSuffixes() []string
	// Coverage documents enforcement depth ("full" | "partial" plus notes).
	Coverage() string
	// InspectRequest returns a Hit when the request violates a restriction for this app.
	InspectRequest(ctx context.Context, req *http.Request, r policy.CASBRestriction) *Hit
	// InspectResponse returns a Hit when the response violates a restriction for this app.
	InspectResponse(ctx context.Context, req *http.Request, resp *http.Response, r policy.CASBRestriction) *Hit
}

// restrictionHas reports whether r.Actions contains action (case-insensitive).
func restrictionHas(r policy.CASBRestriction, action string) bool {
	want := strings.ToLower(strings.TrimSpace(action))
	for _, a := range r.Actions {
		if strings.ToLower(strings.TrimSpace(a)) == want {
			return true
		}
	}
	return false
}

// appMatch reports whether restriction.App refers to detectorApp.
func appMatch(restrictionApp, detectorApp string) bool {
	return strings.EqualFold(strings.TrimSpace(restrictionApp), strings.TrimSpace(detectorApp))
}
