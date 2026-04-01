import type { NextConfig } from 'next';

// ── Security headers added to every response ───────────────────────────────
const securityHeaders = [
  // Prevent the site from being embedded in iframes (clickjacking)
  { key: 'X-Frame-Options', value: 'DENY' },
  // Full Content Security Policy
  // - form-action 'self'     → fixes ZAP "CSP: Failure to Define Directive with No Fallback"
  // - frame-ancestors 'none' → blocks iframe embedding (replaces X-Frame-Options)
  // - default-src 'self'     → baseline: only allow same origin
  // - script-src             → 'unsafe-inline' + 'unsafe-eval' required by Next.js runtime
  // - style-src              → 'unsafe-inline' required by Tailwind / CSS-in-JS
  // - img-src                → data: and blob: needed for Next.js image optimisation
  // - connect-src            → allows API calls to same origin
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self'",
      "connect-src 'self'",
      "form-action 'self'",        // ← fixes ZAP alert (no fallback to default-src)
      "frame-ancestors 'none'",    // ← blocks iframe embedding
      "base-uri 'self'",           // ← prevents base tag hijacking
      "object-src 'none'",         // ← disables Flash / plugins
    ].join('; '),
  },
  // Prevent MIME-type sniffing
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  // Force HTTPS for 1 year (only active once your SSL cert is live)
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
  // Control referrer information sent with requests
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  // Disable access to camera, microphone and geolocation
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
];

const nextConfig: NextConfig = {
  // ✅ FIX for ZAP alert "Server Leaks Information via X-Powered-By"
  // Removes the "X-Powered-By: Next.js" header from every response
  // CWE-497 | WASC-13 | Risk: Low
  poweredByHeader: false,

  async headers() {
    return [
      {
        // Apply security headers to every route
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
