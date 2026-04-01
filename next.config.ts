import type { NextConfig } from 'next';

const securityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' },

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
      "worker-src 'none'",       
      "manifest-src 'self'",     
      "media-src 'none'",        
    ].join('; '),
  },

  // ── MIME-type sniffing prevention ────────────────────────────────────────
  { key: 'X-Content-Type-Options', value: 'nosniff' },

  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },

  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },

  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },

  { key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate, proxy-revalidate' },
];

const nextConfig: NextConfig = {
 
  poweredByHeader: false,

  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
      {
        source: '/api/(.*)',
        headers: [
          { key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate' },
          { key: 'Pragma', value: 'no-cache' },
        ],
      },
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
