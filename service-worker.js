// PlanOS Service Worker (PWA)
// Cache-first for app shell, network-first for everything else (simple + reliable)

const CACHE_NAME = "planos-pwa-v1";
const ASSETS = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./fonts/IRANSansX-Light.woff2",
  "./fonts/IRANSansX-Medium.woff2",
  "./fonts/IRANSansX-DemiBold.woff2",
  "./fonts/IRANSansX-Bold.woff2",
  "./fonts/IRANSansX-ExtraBold.woff2"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.map((k) => (k === CACHE_NAME ? null : caches.delete(k))))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;

  // Single-page app navigation: serve cached index.html
  if (req.mode === "navigate") {
    event.respondWith(
      caches.match("./index.html").then((cached) => cached || fetch(req))
    );
    return;
  }

  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;

      return fetch(req).then((res) => {
        // cache same-origin GET requests
        try {
          const url = new URL(req.url);
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
