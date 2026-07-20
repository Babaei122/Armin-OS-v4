// PlanOS Service Worker (PWA)
// Cache-first for app shell, network-first for everything else (simple + reliable)

const CACHE_NAME = "planos-pwa-v7";
const RUNTIME_CACHE = "planos-runtime-v6";
const ASSETS = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./assets/brand/planos-orbit-mark.png",
  "./assets/brand/daily-insight-orbit.png",
  "./assets/brand/daily-insight-orbit-dark.png",
  "./assets/brand/daily-insight-orbit-mobile.png",
  "./assets/brand/daily-insight-orbit-mobile-dark.png",
  "./fonts/IRANSansX-Light.woff2",
  "./fonts/IRANSansX-Medium.woff2",
  "./fonts/IRANSansX-DemiBold.woff2",
  "./fonts/IRANSansX-Bold.woff2",
  "./fonts/IRANSansX-ExtraBold.woff2"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => Promise.all(ASSETS.map((asset) => cache.add(asset))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.map((k) => ([CACHE_NAME, RUNTIME_CACHE].includes(k) ? null : caches.delete(k))))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;

  // Navigation is network-first so users see releases immediately; offline falls back to the app shell.
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req).then((response) => {
        if (response.ok) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put("./index.html", copy));
        }
        return response;
      }).catch(() => caches.match("./index.html"))
    );
    return;
  }

  const url = new URL(req.url);
  const isChartJs = url.hostname === "cdn.jsdelivr.net" && url.pathname.includes("/chart.js@");
  const isTablerAsset = url.hostname === "cdn.jsdelivr.net" && url.pathname.includes("/@tabler/icons-webfont@");
  if (isChartJs || isTablerAsset) {
    event.respondWith(
      caches.open(RUNTIME_CACHE).then(async (cache) => {
        const cached = await cache.match(req);
        const network = fetch(req).then((response) => {
          if (response.ok) cache.put(req, response.clone());
          return response;
        }).catch(() => cached);
        return cached || network;
      })
    );
    return;
  }

  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;

      return fetch(req).then((res) => {
        // cache same-origin GET requests
        try {
          if (req.method === "GET" && url.origin === self.location.origin) {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
          }
        } catch (_) {}
        return res;
      }).catch(() => cached);
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      const existing = clients[0];
      if (existing) return existing.focus();
      return self.clients.openWindow("./");
    })
  );
});
