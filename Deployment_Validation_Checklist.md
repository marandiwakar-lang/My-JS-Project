# 🚀 Production Deployment Validation Checklist 

---

## 🔐 1. Non-root User with Sudo Access

**Command:**
```bash
id devops
```

**Expected Output:**
```
uid=1001(devops) gid=1001(devops) groups=1001(devops),27(sudo)
```

✅ App should NOT run as root. `devops` must have sudo access.

---

## ⚙️ 2. Application Running as Non-root

**Command:**
```bash
ps aux | grep "node\|pm2\|next" | grep -v grep
```

**Expected:**
- All processes run under `devops`
- No `root` user

---

## 🔥 3. UFW Firewall Configuration

**Command:**
```bash
sudo ufw status verbose
```

**Expected Output:**
```
Status: active

22   ALLOW IN   Anywhere
80   ALLOW IN   Anywhere
443  ALLOW IN   Anywhere
```

---

## 🔑 4. Secure SSH Configuration

**Command:**
```bash
sudo sshd -T | grep -E "passwordauthentication|permitrootlogin|maxauthtries"
```

**Expected:**
```
passwordauthentication no
permitrootlogin no
maxauthtries 3
```

---

## 🟢 5. Node.js via NVM

**Command:**
```bash
sudo -u devops bash -c 'source ~/.nvm/nvm.sh && node --version'
```

**Expected:**
```
v20.x.x
```

---

## ⚡ 6. PM2 Process Manager

**Check App Status:**
```bash
sudo -u devops bash -c 'source ~/.nvm/nvm.sh && pm2 list'
```

**Expected:**
- `nextjs-app` → online

**Check Auto-start:**
```bash
systemctl status pm2-devops
```

**Expected:**
```
active (running)
enabled
```

---

## 🌐 7. Nginx Reverse Proxy

**Test Config:**
```bash
sudo nginx -t
```

**Expected:**
```
syntax is ok
test is successful
```

**Check Status:**
```bash
sudo systemctl status nginx
```

**Expected:**
```
active (running)
```

---

## 🔒 8. SSL Certificate (HTTPS)

**Command:**
```bash
sudo certbot certificates
```

**Expected:**
```
Certificate Name: myjavascriptapp.duckdns.org
Expiry Date: <future date>
Path: /etc/letsencrypt/live/...
```

---

## 🔁 9. HTTP → HTTPS Redirect

**Commands:**
```bash
curl -I http://myjavascriptapp.duckdns.org
```

**Expected:**
```
301 Moved Permanently
```

```bash
curl -I https://myjavascriptapp.duckdns.org
```

**Expected:**
```
200 OK
```

---

## 🛡️ 10. Security Headers

**Command:**
```bash
curl -I https://myjavascriptapp.duckdns.org | grep -i -E "x-frame|x-content|strict-transport|content-security"
```

**Expected:**
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: frame-ancestors 'none'
```

---

## 🚫 11. Block `.git` Directory

**Command:**
```bash
curl -I https://myjavascriptapp.duckdns.org/.git/config
```

**Expected:**
```
404 Not Found
```

---

## 🚫 12. Block `.env` File

**Command:**
```bash
curl -I https://myjavascriptapp.duckdns.org/.env
```

**Expected:**
```
404 Not Found
```

---

## 🏆 13. SSL Grade (Optional)

**Command:**
```bash
curl -s "https://api.ssllabs.com/api/v3/analyze?host=myjavascriptapp.duckdns.org&startNew=on" | grep -o '"grade":"[A-Z+]*"' | head -1
```

**Expected:**
```
"A" or "A+"
```

---

## ⚠️ 14. Rate Limiting Test

**Command:**
```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  https://myjavascriptapp.duckdns.org/api/sendgrid \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"x@x.com","phone":"0000000000","message":"spam"}'
done
```

**Expected:**
- Without protection → 200 responses
- With protection → 429 Too Many Requests

---

## 🔁 15. PM2 Auto Restart After Reboot

**Command:**
```bash
sudo reboot
```

After reboot:
```bash
sudo -u devops bash -c 'source ~/.nvm/nvm.sh && pm2 list'
```

**Expected:**
- App still online

---

# 🎯 Final Summary

This checklist ensures:
- 🔐 Secure server setup
- ⚙️ Proper process management
- 🌐 Production-ready deployment
- 🔁 High availability
- 🛡️ Security best practices

---

## 💡 Interview Tip

If asked how you validate a production deployment:

> I verify user permissions, process ownership, firewall rules, SSH hardening, reverse proxy setup, SSL validity, security headers, and application resilience like auto-restart using PM2.

