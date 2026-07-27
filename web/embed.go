package web

import "embed"

// Dist holds built admin SPA static assets.
// The scaffold ships a placeholder index; the full React app replaces dist/ later.
//
//go:embed all:dist
var Dist embed.FS
