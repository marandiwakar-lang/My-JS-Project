# Deployment Guide

> **Stack:** Next.js · Node 18 · PM2 · Nginx · AWS EC2 (Ubuntu 22.04 LTS)  

---

## Table of Contents

1. Server Provisioning
2. Initial Setup
3. Secure SSH
4. Firewall Configuration
5. Install Dependencies
6. Deploy Application
7. Configure Nginx
8. Enable HTTPS
9. Verification Checklist

---

## 1. Server Provisioning

Provision a new EC2 instance with the following configuration:

| Parameter     | Value                  |
|---------------|------------------------|
| AMI           | Ubuntu 22.04 LTS       |
| Instance Type | t2.micro               |
| Storage       | 20 GB gp3 (recommended)|
| Key Pair      | Create or select existing `.pem` key |

> **Note:** Attach a security group that allows inbound traffic on ports `2222` (SSH), `80` (HTTP), and `443` (HTTPS) only.

---

## 2. Initial Setup

### 2.1 Connect to the Server

```bash
ssh -i key.pem ubuntu@<EC2-IP>
```

### 2.2 Create a Non-Root Deploy User

```bash
# Create the devops user
sudo adduser devops

# Grant sudo privileges
sudo usermod -aG sudo devops

# Switch to devops user for all subsequent steps
su - devops
```

> ⚠️ **Security:** All application processes should run as `devops`, never as `root`.

---

## 3. Secure SSH

### 3.1 Edit SSH Daemon Configuration

```bash
sudo vi /etc/ssh/sshd_config
```

Apply the following changes:

```sshconfig
# Disable direct root login
PermitRootLogin no

# Disable password authentication (key-based auth only)
PasswordAuthentication no

# Move SSH off default port
Port 2222
```

### 3.2 Restart SSH Service

```bash
sudo systemctl restart ssh
```

---

## 4. Firewall Configuration

Configure UFW to allow only necessary traffic:

```bash
# Allow custom SSH port
sudo ufw allow 2222/tcp

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable the firewall
sudo ufw enable

# Verify rules
sudo ufw status verbose
```

Expected output:

```
Status: active

To                         Action      From
--                         ------      ----
2222/tcp                   ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
```

---

## 5. Install Dependencies

### 5.1 Install Node.js via NVM

```bash
# Download and run the NVM install script
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash

# Reload shell environment
source ~/.bashrc

# Install Node.js 18 (LTS)
nvm install 18

# Verify installation
node --version   # Expected: v18.x.x
npm --version
```

### 5.2 Install PM2 (Process Manager)

PM2 is a production process manager for Node.js applications.
Think of it like a supervisor that keeps your app running 24/7.

```bash
npm install -g pm2

# Verify installation
pm2 --version
```

### 5.3 Install Nginx

```bash
sudo apt update
sudo apt install nginx -y

# Verify Nginx is running
sudo systemctl status nginx
```

---

## 6. Deploy Application

### 6.1 Clone Repository and Install

```bash
# Clone your repository
git clone https://github.com/marandiwakar-lang/js-webapp.git
cd js-webapp

# Install production dependencies
npm install

# Build the Next.js application
npm run build
```

### 6.2 Start Application with PM2

```bash
# Start the app under PM2
pm2 start npm --name "nextjs-app" -- start

# Persist PM2 process list across reboots
pm2 save

# Generate and configure PM2 startup script
pm2 startup
# Copy and run the command that PM2 outputs
```

### 6.3 Verify the Application is Running

```bash
# Check process status
pm2 list

# View application logs
pm2 logs nextjs-app

# Confirm the app is listening on port 3000
curl http://localhost:3000
```

---

## 7. Configure Nginx

### 7.1 Edit the Nginx Server Block

```bash
sudo vi /etc/nginx/sites-available/default
```

Replace the file contents with the following configuration:

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # Security headers
    add_header X-Frame-Options "DENY";
    add_header X-Content-Type-Options "nosniff";
    add_header Referrer-Policy "strict-origin-when-cross-origin";

    # Block .git and hidden directories
    location ~ /\.git {
        deny all;
        return 404;
    }

    location ~ /\. {
        deny all;
        return 404;
    }

    # Proxy all traffic to Next.js
    location / {
        proxy_pass         http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection 'upgrade';
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### 7.2 Test and Reload Nginx

```bash
# Test configuration for syntax errors
sudo nginx -t

# Expected output:
# nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# nginx: configuration file /etc/nginx/nginx.conf test is successful

# Reload Nginx to apply changes
sudo systemctl reload nginx
```

---

## 8. Enable HTTPS

Provision a free TLS certificate via Let's Encrypt using Certbot:

```bash
# Install Certbot and the Nginx plugin
sudo apt install certbot python3-certbot-nginx -y

# Obtain and install the certificate
sudo certbot --nginx -d myjavascriptapp.duckdns.org
```

Certbot will:
- Automatically obtain a certificate from Let's Encrypt
- Modify the Nginx config to redirect HTTP → HTTPS
- Configure auto-renewal via a systemd timer

### 8.1 Verify Auto-Renewal

```bash
# Test the renewal process (dry run)
sudo certbot renew --dry-run
```

---

## 9. Verification Checklist

Run the following checks to confirm the deployment is healthy:

```bash
# 1. Confirm HTTPS is accessible
curl -I https://myjavascriptapp.duckdns.org 
# Expected: HTTP/2 200

# 2. Confirm .git directory is blocked
curl -I https://myjavascriptapp.duckdns.org /.git/config
# Expected: HTTP/2 404

# 3. Check PM2 process status
pm2 list
# Expected: nextjs-app — status: online

# 4. Check firewall rules
sudo ufw status
# Expected: 2222, 80, 443 ALLOW

# 5. Verify SSH on new port (from a separate terminal)
ssh -i key.pem -p 2222 devops@<EC2-IP>

# 6. Check Nginx is active
sudo systemctl status nginx
# Expected: active (running)
```

### Deployment Health Summary

| Check                      | Command                         | Expected Result      |
|----------------------------|---------------------------------|----------------------|
| HTTPS response             | `curl -I https://myjsapp.com`| `HTTP/2 200`         |
| `.git` directory blocked   | `curl -I .../git/config`        | `HTTP/2 404`         |
| PM2 process running        | `pm2 list`                      | `online`             |
| Firewall active            | `sudo ufw status`               | `active`             |
| Nginx running              | `sudo systemctl status nginx`   | `active (running)`   |
| Certificate valid          | `sudo certbot certificates`     | Not expired          |

---


