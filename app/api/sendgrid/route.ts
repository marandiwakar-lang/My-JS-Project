import { NextResponse } from 'next/server';
import sendgrid from '@sendgrid/mail';
import { z } from 'zod';

// ── 1. Input validation schema ──────────────────────────────────────────────
const ContactSchema = z.object({
  name:    z.string().min(2).max(100).regex(/^[a-zA-Z\s'-]+$/, 'Invalid name'),
  email:   z.string().email('Invalid email').max(254),
  phone:   z.string().regex(/^\+?[\d\s\-().]{7,20}$/, 'Invalid phone number'),
  message: z.string().min(10, 'Message too short').max(2000, 'Message too long'),
});

// ── 2. CRLF sanitizer — prevents email header injection ────────────────────
function sanitize(value: string, max = 200): string {
  return String(value).replace(/[\r\n\t]/g, ' ').trim().slice(0, max);
}

// ── FIX 3: HTML escaper — prevents HTML injection in email body ─────────────
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ── FIX 1: Rate limiting — prevents inbox flooding ──────────────────────────
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT = 5;      // max 5 requests
const WINDOW_MS  = 60000;  // per 60 seconds

function isRateLimited(ip: string): boolean {
  const now   = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry || now > entry.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + WINDOW_MS });
    return false;
  }
  if (entry.count >= RATE_LIMIT) return true;
  entry.count++;
  return false;
}

export async function POST(req: Request) {

  // ── FIX 1 applied: check rate limit before processing anything ─────────────
  const ip = req.headers.get('x-real-ip')
          ?? req.headers.get('x-forwarded-for')?.split(',')[0].trim()
          ?? 'unknown';

  if (isRateLimited(ip)) {
    return NextResponse.json(
      { error: 'Too many requests. Please try again later.' },
      { status: 429 }
    );
  }

  try {
    const body = await req.json();

    // ── 3. Validate all fields before doing anything ───────────────────────
    const result = ContactSchema.safeParse(body);
    if (!result.success) {
      return NextResponse.json(
        { error: 'Validation failed', details: result.error.flatten().fieldErrors },
        { status: 400 }
      );
    }

    // ── 4. Sanitize validated data to strip any CRLF characters ───────────
    const safeName    = sanitize(result.data.name, 100);
    const safeEmail   = sanitize(result.data.email, 254);
    const safePhone   = sanitize(result.data.phone, 20);
    const safeMessage = sanitize(result.data.message, 2000);

    // ── FIX 3 applied: HTML-escape for use inside HTML email body ──────────
    const htmlName    = escapeHtml(safeName);
    const htmlEmail   = escapeHtml(safeEmail);
    const htmlPhone   = escapeHtml(safePhone);
    const htmlMessage = escapeHtml(safeMessage);

    const apiKey  = process.env.SENDGRID_API_KEY;
    const toEmail = process.env.SENDGRID_TO_EMAIL;

    // ── FIX 2 applied: generic error — no internal service names leaked ─────
    if (!apiKey || !toEmail) {
      console.error('SendGrid environment variables are not configured');
      return NextResponse.json(
        { error: 'Service temporarily unavailable. Please try again later.' },
        { status: 500 }
      );
    }

    sendgrid.setApiKey(apiKey);

    // ── 5. Use sanitized + escaped variables — never raw body data ─────────
    const msg = {
      to:      toEmail,
      from:    toEmail,
      subject: 'New Contact Form Submission',
      // Plain-text version uses safe* (no HTML needed)
      text: `Name: ${safeName}\nEmail: ${safeEmail}\nPhone: ${safePhone}\nMessage: ${safeMessage}`,
      // HTML version uses html* (HTML-escaped)
      html: `
        <html>
          <body style="background: #f6f6f7; padding: 40px 0;">
            <div style="max-width: 480px; margin: 40px auto; background: #fff; border-radius: 18px; box-shadow: 0 2px 8px rgba(0,0,0,0.04); padding: 32px 32px 24px 32px; font-family: Arial, sans-serif;">
              <div style="text-align: center; margin-bottom: 24px;">
                <div style="font-size: 22px; font-weight: bold; letter-spacing: 1px; color: #222;">NILAVAN REALTORS</div>
              </div>
              <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;" />
              <div style="font-size: 16px; color: #222; margin-bottom: 24px;">
                <p style="margin: 0 0 16px 0;">You have a new contact form submission:</p>
                <p style="margin: 0 0 8px 0;"><strong>Name:</strong> ${htmlName}</p>
                <p style="margin: 0 0 8px 0;"><strong>Email:</strong> ${htmlEmail}</p>
                <p style="margin: 0 0 8px 0;"><strong>Phone:</strong> ${htmlPhone}</p>
                <p style="margin: 0 0 8px 0;"><strong>Message:</strong> ${htmlMessage}</p>
              </div>
            </div>
          </body>
        </html>
      `,
    };

    await sendgrid.send(msg);
    return NextResponse.json({ success: true });

  } catch (error: unknown) {
    console.error('SendGrid Error:', error);

    if (error && typeof error === 'object' && 'response' in error) {
      const sgError = error as { response?: { body?: unknown } };
      console.error('SendGrid Response Body:', sgError.response?.body);
    }

    // Generic error — no internal details exposed to the client
    return NextResponse.json(
      { error: 'Something went wrong. Please try again later.' },
      { status: 500 }
    );
  }
}
