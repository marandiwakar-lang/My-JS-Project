// middleware.ts  (project root)
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

const rateLimit = new Map<string, { count: number; start: number }>()
const WINDOW_MS = 60_000   // 1 minute
const MAX_REQUESTS = 5     // 5 submissions per IP per minute

export function middleware(req: NextRequest) {
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0] ?? 'unknown'
  const now = Date.now()
  const entry = rateLimit.get(ip) ?? { count: 0, start: now }

  if (now - entry.start > WINDOW_MS) {
    entry.count = 0
    entry.start = now
  }

  entry.count++
  rateLimit.set(ip, entry)

  if (entry.count > MAX_REQUESTS) {
    return NextResponse.json(
      { error: 'Too many requests. Please try again later.' },
      { status: 429 }
    )
  }

  return NextResponse.next()
}

export const config = {
  matcher: '/api/contact',   // adjust path to match your actual API route folder name
}
