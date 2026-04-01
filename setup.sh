#!/bin/bash
set -e

echo "🚀 Starting Server Setup..."

# -----------------------------
# VARIABLES (EDIT THESE)
# -----------------------------
USERNAME="devops"
REPO_URL="https://github.com/marandiwakar-lang/js-webapp.git"
APP_DIR="/home/$USERNAME/js-webapp"

# -----------------------------
# 1. CREATE USER
# -----------------------------
if ! id "$USERNAME" &>/dev/null; then
    echo "Creating user: $USERNAME"
    sudo adduser --disabled-password --gecos "" $USERNAME
    sudo usermod -aG sudo $USERNAME
fi

# -----------------------------
# 2. SSH HARDENING
# -----------------------------
echo "Configuring SSH security..."

sudo sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config

sudo systemctl restart ssh

# -----------------------------
# 3. FIREWALL SETUP
# -----------------------------
echo "Configuring firewall..."

sudo ufw allow 2222/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# -----------------------------
# 4. INSTALL PACKAGES
# -----------------------------
echo "Installing dependencies..."

sudo apt update -y
sudo apt install -y nginx git curl

# -----------------------------
# 5. SETUP NODE + PM2 (AS DEVOPS USER)
# -----------------------------
echo "Setting up Node.js and PM2..."

sudo -u $USERNAME bash << 'EOF'

set -e

export NVM_DIR="$HOME/.nvm"

# Install NVM if not exists
if [ ! -d "$NVM_DIR" ]; then
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash
fi

source "$NVM_DIR/nvm.sh"

# Install Node
nvm install 18
nvm use 18

# Install PM2
npm install -g pm2

EOF

# -----------------------------
# 6. DEPLOY APP
# -----------------------------
echo "Deploying application..."

sudo -u $USERNAME bash << EOF

set -e
cd ~

# Clone repo if not exists
if [ ! -d "$APP_DIR" ]; then
  git clone $REPO_URL $APP_DIR
fi

cd $APP_DIR

git fetch origin
git reset --hard origin/main

npm install
npm run build

pm2 restart nextjs-app || pm2 start npm --name "nextjs-app" -- start
pm2 save

EOF

# -----------------------------
# 7. PM2 AUTO START
# -----------------------------
echo "Configuring PM2 startup..."

sudo env PATH=$PATH:/home/$USERNAME/.nvm/versions/node/v18*/bin \
pm2 startup systemd -u $USERNAME --hp /home/$USERNAME || true

# -----------------------------
# 8. NGINX CONFIG
# -----------------------------
echo "Configuring Nginx..."

sudo tee /etc/nginx/sites-available/default > /dev/null << 'NGINXEOF'

server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
    }
}

NGINXEOF

sudo nginx -t
sudo systemctl restart nginx

echo "✅ Setup completed successfully!"
