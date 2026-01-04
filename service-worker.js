"use strict";

const CACHE_NAME = 'arminos-static-v1';
const ALLOWED_ORIGIN = self.location.origin;

// Security-focused service worker
// - Network-first for most requests with cache fallback
// - Adds conservative security headers to same-origin responses
// - Sanitizes calendar API JSON payloads to reduce XSS risk
// - Forwards confirm-delete messages to clients (the SW cannot show UI)

self.addEventListener('install', event => {
  // Activate worker as soon as it's finished installing
  self.skipWaiting();
  event.waitUntil(caches.open(CACHE_NAME));
});

self.addEventListener('activate', event => {
  // Claim clients and remove old caches
  event.waitUntil((async () => {
    await self.clients.claim();
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)));
  })());
});

function isSameOrigin(request) {
  try {
    return new URL(request.url).origin === ALLOWED_ORIGIN;
  } catch (e) {
    return false;
  }
}

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  // HSTS is effective only over HTTPS; include for hardened responses
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'
};

self.addEventListener('fetch', event => {
  const req = event.request;

  // Only intervene for safe methods and same-origin requests
  if (req.method !== 'GET' || !isSameOrigin(req)) {
    return; // let the network handle it
  }

  // Navigation / HTML responses: ensure security headers are present
  if (req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html')) {
    event.respondWith(handleNavigationRequest(req));
    return;
  }

  // Harden the calendar API responses to prevent XSS vectors
  try {
    const pathname = new URL(req.url).pathname;
    if (pathname.startsWith('/api/calendar')) {
      event.respondWith(handleApiCalendar(req));
      return;
    }
  } catch (e) {
    // ignore URL parsing errors and continue to default handling
  }

  // Default behaviour: network-first with cache fallback and security headers
  event.respondWith(networkFirstWithSecurity(req));
});

async function addSecurityHeadersToResponse(response) {
  if (!response) return response;
  const newHeaders = new Headers(response.headers);
  Object.entries(SECURITY_HEADERS).forEach(([k, v]) => newHeaders.set(k, v));
  // Avoid leaking server details
  newHeaders.delete('Server');
  const body = await response.arrayBuffer();
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}

async function handleNavigationRequest(request) {
  try {
    const networkResponse = await fetch(request);
    if (!networkResponse) throw new Error('Empty network response');
    if (networkResponse.status >= 500) throw new Error('Server error');
    return await addSecurityHeadersToResponse(networkResponse);
  } catch (err) {
    // Fallback to a cached offline page if available
    const cache = await caches.open(CACHE_NAME);
    const cached = await cache.match('/offline.html');
    if (cached) return await addSecurityHeadersToResponse(cached);
    return new Response('<h1>Offline</h1>', {
      headers: Object.assign({'Content-Type': 'text/html'}, SECURITY_HEADERS),
      status: 503,
      statusText: 'Service Unavailable'
    });
  }
}

async function handleApiCalendar(request) {
  try {
    const resp = await fetch(request);
    if (!resp) return resp;
    const contentType = resp.headers.get('Content-Type') || '';
    if (contentType.includes('application/json')) {
      // Parse and sanitize JSON payloads to remove potential HTML/script fragments
      const json = await resp.json();
      const sanitized = sanitizeJsonStrings(json);
      const headers = new Headers(resp.headers);
      Object.entries(SECURITY_HEADERS).forEach(([k, v]) => headers.set(k, v));
      return new Response(JSON.stringify(sanitized), {
        status: resp.status,
        statusText: resp.statusText,
        headers: headers
      });
    }
    // For non-JSON responses, just attach security headers
    return await addSecurityHeadersToResponse(resp);
  } catch (err) {
    return new Response(JSON.stringify({error: 'Network error'}), {
      status: 502,
      headers: Object.assign({'Content-Type': 'application/json'}, SECURITY_HEADERS)
    });
  }
}

function sanitizeJsonStrings(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return sanitizeString(obj);
  if (Array.isArray(obj)) return obj.map(sanitizeJsonStrings);
  if (typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = sanitizeJsonStrings(v);
    }
    return out;
  }
  return obj;
}

function sanitizeString(s) {
  // Best-effort sanitizer: remove <script> tags, inline event handlers and javascript: URIs
  // IMPORTANT: This is a defense-in-depth measure. Primary sanitization should happen server-side
  return s
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
    .replace(/on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/javascript:/gi, '');
}

async function networkFirstWithSecurity(request) {
  const cache = await caches.open(CACHE_NAME);
  try {
    const response = await fetch(request);
    if (response && response.ok) {
      // cache a clone for offline usage
      cache.put(request, response.clone()).catch(() => {});
      return await addSecurityHeadersToResponse(response);
    }
    const cached = await cache.match(request);
    if (cached) return await addSecurityHeadersToResponse(cached);
    return response;
  } catch (err) {
    const cached = await cache.match(request);
    if (cached) return await addSecurityHeadersToResponse(cached);
    // propagate error to caller (browser)
    throw err;
  }
}

// Message handling - strictly verify client origin before acting
self.addEventListener('message', event => {
  try {
    const data = event.data;
    const src = event.source;
    if (!src || !src.url) return;
    if (new URL(src.url).origin !== ALLOWED_ORIGIN) return;
    if (!data || typeof data !== 'object') return;

    if (data.type === 'CONFIRM_DELETE') {
      // The SW cannot show modal confirmations; forward the intent to all controlled clients
      // Clients should show a user-facing confirmation UI before performing deletion.
      self.clients.matchAll({includeUncontrolled: true, type: 'window'}).then(clients => {
        clients.forEach(client => client.postMessage({type: 'CONFIRM_DELETE', payload: {projectId: data.projectId}}));
      });
    }

    if (data.type === 'SW_HEALTH_CHECK') {
      // Respond directly to the sender
      src.postMessage({type: 'SW_HEALTH_OK', version: CACHE_NAME});
    }
  } catch (e) {
    // Do not leak details to clients
  }
});
