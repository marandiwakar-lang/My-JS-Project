// pages/api/sendgrid.ts
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '1 m'),
})

export default async function handler(req, res) {
  const ip = req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? 'unknown'
  const { success, limit, remaining } = await ratelimit.limit(ip)

  if (!success) {
    return res.status(429).json({
      error: 'Too many requests. Please wait before submitting again.',
      limit,
      remaining,
    })
  }

  // ... rest of handler
}
