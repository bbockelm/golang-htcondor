package webui

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// NewSPAHandler returns an http.Handler that serves the embedded frontend.
// It resolves Next.js static-export dynamic routes (e.g. [id] -> _) and
// falls back to index.html for client-side routing.
//
// When the frontend is not embedded (no embed_frontend build tag), the
// returned handler responds with 404 so the caller can fall back to a
// non-SPA welcome page.
func NewSPAHandler() http.Handler {
	fsys, _ := DistFS()
	if fsys == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Frontend not embedded in this build", http.StatusNotFound)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlPath := strings.TrimPrefix(r.URL.Path, "/")
		if urlPath == "" {
			urlPath = "index.html"
		}

		// 1. Exact file (static assets, known pages).
		if fileExists(fsys, urlPath) {
			serveFile(w, r, fsys, urlPath)
			return
		}

		// 2. With .html extension (e.g. /jobs -> jobs.html).
		if !strings.Contains(path.Base(urlPath), ".") {
			if fileExists(fsys, urlPath+".html") {
				serveFile(w, r, fsys, urlPath+".html")
				return
			}
		}

		// 3. Next.js dynamic routes: replace non-matching segments with _.
		if resolved := resolveDynamicRoute(fsys, urlPath); resolved != "" {
			serveFile(w, r, fsys, resolved)
			return
		}

		// 4. SPA fallback for client-side routing.
		serveFile(w, r, fsys, "index.html")
	})
}

// resolveDynamicRoute attempts to match a URL path against Next.js static
// export dynamic route files. For [param] routes, Next.js generates files
// using _ as the placeholder (e.g. jobs/[id] -> jobs/_.html).
func resolveDynamicRoute(fsys fs.FS, urlPath string) string {
	suffix := ".html"
	if strings.HasSuffix(urlPath, ".txt") {
		suffix = ".txt"
		urlPath = strings.TrimSuffix(urlPath, ".txt")
	}

	segments := strings.Split(urlPath, "/")
	if len(segments) == 0 {
		return ""
	}

	resolved := make([]string, 0, len(segments))
	for i, seg := range segments {
		isLast := i == len(segments)-1

		if isLast {
			for _, candidate := range []string{seg, "_"} {
				filePath := strings.Join(append(resolved, candidate), "/") + suffix
				if fileExists(fsys, filePath) {
					return filePath
				}
			}
			return ""
		}

		literalDir := strings.Join(append(resolved, seg), "/")
		wildcardDir := strings.Join(append(resolved, "_"), "/")

		switch {
		case dirExists(fsys, literalDir):
			resolved = append(resolved, seg)
		case dirExists(fsys, wildcardDir):
			resolved = append(resolved, "_")
		default:
			return ""
		}
	}

	return ""
}

func fileExists(fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return !stat.IsDir()
}

func dirExists(fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return stat.IsDir()
}

// serveFile is the single chokepoint for handing a path to
// http.ServeFileFS. The embed.FS we serve from already rejects
// "../" segments, but gosec G703 flags any user-controlled string
// that flows into a file-serving function regardless. Validate
// explicitly here so the security guarantee is local to this
// function rather than implicit in the FS implementation: only
// names that pass path.Clean unchanged AND contain no "..", "//",
// or leading "/" are served. Anything else gets a 404.
//
// In practice the callers (NewSPAHandler, resolveDynamicRoute)
// produce only safe names — they're built from the embed manifest
// after a fileExists check. The validation here is defense in
// depth.
func serveFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) {
	if !isSafeEmbeddedPath(name) {
		http.NotFound(w, r)
		return
	}
	// gosec G703: name is validated by isSafeEmbeddedPath above; the
	// taint tracker doesn't follow the check across the function
	// boundary. The validation rejects "..", absolute paths, NULs,
	// and anything path.Clean would alter — embed.FS rejects them
	// all anyway, so this is defense in depth.
	http.ServeFileFS(w, r, fsys, name) //nolint:gosec
}

// isSafeEmbeddedPath reports whether name is safe to pass to
// http.ServeFileFS over an embed.FS rooted at the package's dist
// directory. The rules: relative path, no ".." segments, no
// double-slashes, no NUL bytes. A nonzero name is required.
func isSafeEmbeddedPath(name string) bool {
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "/") {
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	if strings.Contains(name, "//") {
		return false
	}
	if strings.ContainsRune(name, 0) {
		return false
	}
	if path.Clean(name) != name {
		return false
	}
	return true
}
