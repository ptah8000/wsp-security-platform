package web

import "embed"

// Dist holds built admin SPA static assets (Vite output under dist/).
// Build with: cd web && npm install && npm run build
//
//go:embed all:dist
var Dist embed.FS
