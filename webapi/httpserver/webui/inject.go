package webui

import (
	"bytes"
	"regexp"
)

// bodyStartRe matches an opening <body> tag, however it is attributed.
var bodyStartRe = regexp.MustCompile(`(?i)<body[^>]*>`)

// injectHead splices a block of HTML into a document's head.
//
// A site app's bundle is told where it is mounted this way, so the
// injection has to land on every page the app can be entered at -- not
// only on well-formed ones. A hand-written index.html with no <head> is
// a plausible thing for a site to ship, and a bundle that never learns
// its base path is broken, so the fallbacks matter more here than they
// would for decoration:
//
//	</head>   splice before it, which is where it belongs
//	<body>    splice after it, for a document with no head
//	neither   prepend, for a fragment
//
// Nothing is escaped: the caller owns the block and is expected to
// have escaped whatever it interpolated.
func injectHead(page, html []byte) []byte {
	if len(html) == 0 {
		return page
	}
	at := -1
	if loc := headEndRe.FindIndex(page); loc != nil {
		at = loc[0]
	} else if loc := bodyStartRe.FindIndex(page); loc != nil {
		at = loc[1]
	}
	if at < 0 {
		return append(append([]byte(nil), html...), page...)
	}
	out := make([]byte, 0, len(page)+len(html))
	out = append(out, page[:at]...)
	out = append(out, html...)
	return append(out, page[at:]...)
}

// looksLikeHTML reports whether a response body should be injected
// into. Used to keep the injection off anything that merely has an
// .html-adjacent name.
func looksLikeHTML(page []byte) bool {
	head := page
	if len(head) > 1024 {
		head = head[:1024]
	}
	lower := bytes.ToLower(head)
	return bytes.Contains(lower, []byte("<html")) ||
		bytes.Contains(lower, []byte("<!doctype html")) ||
		bytes.Contains(lower, []byte("<head")) ||
		bytes.Contains(lower, []byte("<body"))
}
