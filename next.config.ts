import type { NextConfig } from 'next';

// ── Security headers — fixes all actionable ZAP alerts ────────────────────
const securityHeaders = [
  // ── Clickjacking protection (ZAP: X-Frame-Options) ──────────────────────
  { key: 'X-Frame-Options', value: 'DENY' },

  // ── Full Content Security Policy ─────────────────────────────────────────
  // ZAP alert: "CSP: Failure to Define Directive with No Fallback"
  //   Fix: add worker-src, manifest-src, media-src — these don't fallback
  //        to default-src in all browsers, so they must be explicit.
  //
  // ZAP alert: "CSP: Wildcard Directive"
  //   Fix: no wildcard (*) used anywhere in this policy.
  //
  // ZAP alert: "CSP: script-src unsafe-eval"
  //   Status: REQUIRED by Next.js App Router for React hydration.
  //           Cannot be removed without breaking the app.
  //           Documented trade-off — noted in security report.
  //
  // ZAP alert: "CSP: script-src unsafe-inline"
  //   Status: REQUIRED by Next.js runtime and inline event handlers.
  //           Cannot be removed without a full nonce/hash implementation.
  //           Documented trade-off — noted in security report.
  //
  // ZAP alert: "CSP: style-src unsafe-inline"
  //   Status: REQUIRED by Tailwind CSS and CSS-in-JS at runtime.
  //           Cannot be removed without breaking all styles.
  //           Documented trade-off — noted in security report.
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self'",
      "connect-src 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "object-src 'none'",
      // ↓ These three fix "CSP: Failure to Define Directive with No Fallback"
      //   because these directives do NOT fall back to default-src in all browsers
      "worker-src 'none'",       // Web Workers — none needed in this app
      "manifest-src 'self'",     // PWA manifest
      "media-src 'none'",        // Audio/video — none used in this app
    ].join('; '),
  },

  // ── MIME-type sniffing prevention ────────────────────────────────────────
  { key: 'X-Content-Type-Options', value: 'nosniff' },

  // ── HSTS — force HTTPS for 1 year ────────────────────────────────────────
  // ZAP alert: "Strict-Transport-Security Multiple Header Entries"
  //   Fix: set HSTS here in Next.js ONLY.
  //        Remove the add_header Strict-Transport-Security line from Nginx
  //        so only one source sets this header (no duplicates).
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },

  // ── Referrer policy ──────────────────────────────────────────────────────
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },

  // ── Permissions policy ───────────────────────────────────────────────────
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },

  // ── Cache-Control for HTML pages ─────────────────────────────────────────
  // ZAP alert: "Re-examine Cache-control Directives"
  //   Fix: instruct browsers not to cache sensitive page responses.
  //        API routes get their own Cache-Control — see the /api/* rule below.
  { key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate, proxy-revalidate' },
];

const nextConfig: NextConfig = {
  // ── Remove "X-Powered-By: Next.js" header ────────────────────────────────
  // ZAP alert: "Server Leaks Information via X-Powered-By" (CWE-497)
  poweredByHeader: false,

  async headers() {
    return [
      // ── Apply security headers to every page route ──────────────────────
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
      // ── API routes: always no-cache ─────────────────────────────────────
      // ZAP alert: "Re-examine Cache-control Directives"
      //   API responses must never be cached — they contain live data.
      {
        source: '/api/(.*)',
        headers: [
          { key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate' },
          { key: 'Pragma', value: 'no-cache' },
        ],
      },
      // ── Static Next.js assets: long-term cache (immutable) ──────────────
      // These files have content-hashed names — safe to cache forever.
      // This resolves ZAP flagging missing cache headers on /_next/static/.
      {
        source: '/_next/static/(.*)',
        headers: [
          { key: 'Cache-Control', value: 'public, max-age=31536000, immutable' },
        ],
      },
    ];
  },
};

export default nextConfig;
