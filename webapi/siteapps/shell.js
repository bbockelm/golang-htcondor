// The site-app overlay bar: where you are, where else you can go, and
// the way back to the full console.
//
// Served as /site/_shell.js and pulled in by every page a site app
// serves (see head.go). It is embedded into the server rather than
// built, so it is plain ES5-ish script with no bundler and no
// dependencies, and it may load nothing from anywhere else: the access
// point sends Content-Security-Policy: default-src 'self', so an
// external font or stylesheet would simply not load.
//
// Everything it draws goes inside a shadow root with all:initial, which
// is the whole reason this is tolerable. The bar lives in a page
// somebody else wrote, with CSS we have never seen: the shadow root
// means their styles cannot reach in and ours cannot leak out, so we
// are not negotiating specificity with a stranger's build.
(function () {
  "use strict";
  if (window.__HTCONDOR_SHELL__) return;
  window.__HTCONDOR_SHELL__ = true;

  // The bar's height, in one place: the CSS, the custom property the
  // page reads, and the clearance calculation all have to agree, and
  // three literals drift.
  var H = 36;

  // The brand, taken from the web UI's Tailwind theme
  // (webapi/frontend/src/app/globals.css) so the bar is the same red
  // and the same near-black as the console's own navigation rather
  // than an approximation of them:
  //
  //   ink-950   #0a0a0a   the sidebar's background
  //   ink-200   #d1d1d1   a navigation link
  //   ink-300   #b0b0b0   secondary text
  //   ink-600   #5d5d5d   a separator
  //   ink-50    #f6f6f6   the heading
  //   brand-600 #b61f24   a primary button, and the rule under the bar
  //   brand-700 #971c20   that button, hovered
  //   brand-500 #de434a   the mark
  //   brand-400 #ee6b71   the focus ring
  //
  // The typeface is the stack globals.css gives <body>: system fonts,
  // which is also the only stack that needs nothing fetched.

  var meta = document.querySelector('meta[name="htcondor-shell"]');
  if (meta && meta.content === "none") return;

  function h(tag, props, kids) {
    var el = document.createElement(tag);
    for (var k in props) if (props[k] != null) el.setAttribute(k, props[k]);
    (kids || []).forEach(function (c) {
      el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return el;
  }

  function json(url) {
    return fetch(url, { credentials: "include" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; });
  }

  // The branding is what the site calls itself, the same values the
  // console's sidebar heads itself with. Unauthenticated and cheap; a
  // site that configured none gets the default, and a failure here
  // costs the name, not the bar.
  Promise.all([json("/api/v1/auth/me"), json("/api/v1/webui/branding")])
    .then(function (answers) {
      var me = answers[0];
      var branding = answers[1] || {};
      if (!me || !me.authenticated) return;

      var apps = me.site_apps || [];
      var here = (window.__HTCONDOR_APP__ || {}).id;
      var others = apps.filter(function (a) { return a.id !== here; });

      // The way out, and there is always one.
      //
      // An app-only session gets the expert door, which opens the
      // console for this browser session; anybody else already has the
      // console and only needs the link. The earlier version rendered
      // the bar only when there were other apps or an expert door,
      // which left the common case -- one published app, a user with
      // the whole console -- with no bar and no way back at all.
      var leave = me.app_only
        ? { href: "/site/expert", label: "Expert mode", title: "Open the full HTCondor console for this browser session" }
        : { href: "/", label: "Full console", title: "Go to the full HTCondor console" };

      var host = document.createElement("div");
      host.setAttribute("data-htcondor-shell", "");
      var root = host.attachShadow({ mode: "open" });

      var style = document.createElement("style");
      style.textContent =
        ":host{all:initial}" +
        ".bar{position:fixed;top:0;left:0;right:0;height:" + H + "px;z-index:2147483000;" +
        "display:flex;align-items:center;gap:.5rem;padding:0 .75rem;box-sizing:border-box;" +
        "font:400 13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;" +
        "background:#0a0a0a;color:#d1d1d1;border-bottom:1px solid #b61f24}" +
        ".brand{display:flex;align-items:center;gap:.4rem;min-width:0}" +
        ".mark{width:.5rem;height:.5rem;border-radius:999px;background:#de434a;flex:none}" +
        ".site{font-weight:600;color:#f6f6f6;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}" +
        ".sep{color:#5d5d5d;flex:none}" +
        ".app{color:#b0b0b0;margin-right:auto;min-width:0;overflow:hidden;" +
        "text-overflow:ellipsis;white-space:nowrap}" +
        "a{color:#d1d1d1;text-decoration:none;padding:.15rem .5rem;border-radius:.25rem;" +
        "white-space:nowrap;flex:none}" +
        "a:hover{background:rgba(255,255,255,.1);color:#fff}" +
        "a:focus-visible{outline:2px solid #ee6b71;outline-offset:1px}" +
        "a.leave{background:#b61f24;color:#fff;font-weight:500}" +
        "a.leave:hover{background:#971c20}" +
        // Narrow enough and the site's name goes before the app's: on a
        // phone the page you are in and the way out are what matter.
        "@media (max-width:30rem){.site,.sep{display:none}}";
      root.appendChild(style);

      var appName = (window.__HTCONDOR_APP__ || {}).name || "";
      var bar = h("div", { class: "bar", role: "navigation", "aria-label": "HTCondor apps" }, [
        h("span", { class: "brand" }, [
          h("span", { class: "mark", "aria-hidden": "true" }),
          h("span", { class: "site" }, [branding.site_name || "HTCondor"]),
        ]),
      ]);
      if (appName) {
        bar.appendChild(h("span", { class: "sep", "aria-hidden": "true" }, ["/"]));
        bar.appendChild(h("span", { class: "app" }, [appName]));
      } else {
        bar.appendChild(h("span", { class: "app" }, []));
      }
      others.slice(0, 4).forEach(function (a) {
        bar.appendChild(h("a", { href: a.url }, [a.name]));
      });
      if (others.length > 4) bar.appendChild(h("a", { href: "/site/" }, ["All apps"]));
      bar.appendChild(h("a", { class: "leave", href: leave.href, title: leave.title }, [leave.label]));
      root.appendChild(bar);

      document.body.appendChild(host);
      // Tell the page how much room the bar took, and nudge it clear.
      // An app that cares reads the variable; one that does not still
      // gets that much of its first screen back.
      var de = document.documentElement;
      de.style.setProperty("--htcondor-shell-height", H + "px");
      de.style.setProperty("scroll-padding-top", H + "px");
      // Ensure at least the bar's height of clearance, measured from
      // the COMPUTED padding rather than the inline one.
      //
      // The first version checked document.body.style.paddingTop,
      // which is only the inline value, and got both directions
      // wrong: an app with an inline padding of its own was skipped
      // entirely and left with less clearance than the bar needs,
      // while an app whose stylesheet set a generous padding had it
      // overridden down to the bar's height. Reading the computed
      // value fixes both -- a page that already clears the bar is
      // left alone.
      var pad = parseFloat(getComputedStyle(document.body).paddingTop) || 0;
      if (pad < H) document.body.style.paddingTop = H + "px";
    })
    .catch(function () { /* no bar is better than a broken page */ });
})();
