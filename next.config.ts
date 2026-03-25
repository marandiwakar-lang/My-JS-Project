import type { NextConfig } from 'next';

// ── Security headers added to every response ───────────────────────────────
const securityHeaders = [
  // Prevent the site from being embedded in iframes (clickjacking)
  { key: 'X-Frame-Options',           value: 'DENY' },
  // Modern alternative to X-Frame-Options
  { key: 'Content-Security-Policy',   value: "frame-ancestors 'none'" },
  // Prevent MIME-type sniffing
  { key: 'X-Content-Type-Options',    value: 'nosniff' },
  // Force HTTPS for 1 year (only active once your SSL cert is live)
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
  // Control referrer information sent with requests
  { key: 'Referrer-Policy',           value: 'strict-origin-when-cross-origin' },
  // Disable access to camera and microphone
  { key: 'Permissions-Policy',        value: 'camera=(), microphone=()' },
];

const nextConfig: NextConfig = {
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
