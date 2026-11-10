// Package webui embeds the browser UI.
package webui

import "embed"

// FS contains index.html, app.js, style.css, and favicon.svg.
//
//go:embed index.html app.js style.css favicon.svg
var FS embed.FS
