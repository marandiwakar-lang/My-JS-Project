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

export async function POST(req: Request) {
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

    const apiKey  = process.env.SENDGRID_API_KEY;
    const toEmail = process.env.SENDGRID_TO_EMAIL;

    if (!apiKey) {
      console.error('SENDGRID_API_KEY is not set');
      return NextResponse.json(
        { error: 'SendGrid API key not configured' },
        { status: 500 }
      );
    }

    if (!toEmail) {
      console.error('SENDGRID_TO_EMAIL is not set');
      return NextResponse.json(
        { error: 'Recipient email not configured' },
        { status: 500 }
      );
    }

    sendgrid.setApiKey(apiKey);

    // ── 5. Use only sanitized variables — never raw body data ─────────────
    const msg = {
      to:      toEmail,
      from:    toEmail,
      subject: 'New Contact Form Submission',
      text:    `Name: ${safeName}\nEmail: ${safeEmail}\nPhone: ${safePhone}\nMessage: ${safeMessage}`,
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
                <p style="margin: 0 0 8px 0;"><strong>Name:</strong> ${safeName}</p>
                <p style="margin: 0 0 8px 0;"><strong>Email:</strong> ${safeEmail}</p>
                <p style="margin: 0 0 8px 0;"><strong>Phone:</strong> ${safePhone}</p>
                <p style="margin: 0 0 8px 0;"><strong>Message:</strong> ${safeMessage}</p>
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

    return NextResponse.json({ error: 'Error sending email' }, { status: 500 });
  }
}
