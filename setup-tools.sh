#!/bin/bash
# setup-tools.sh - Install WordPress security scanning tools on Linux

echo "=========================================="
echo "Installing WordPress Security Tools"
echo "=========================================="

echo ""
echo "Updating system packages..."
sudo apt update

echo ""
echo "Installing curl..."
sudo apt install -y curl

echo ""
echo "Installing dig (dnsutils)..."
sudo apt install -y dnsutils

echo ""
echo "Installing Ruby and dependencies..."
sudo apt install -y ruby-full zlib1g-dev

echo ""
echo "Installing WPScan..."
cd /opt
sudo git clone https://github.com/wpscanteam/wpscan.git
cd wpscan
sudo bundle install --without test

echo ""
echo "Creating symlink for easy access..."
sudo ln -sf /opt/wpscan/wpscan.rb /usr/local/bin/wpscan

echo ""
echo "=========================================="
echo "Setup complete!"
echo "=========================================="
echo ""
echo "Usage examples:"
echo "  wpscan --url https://example.com --enumerate vp,vt,u"
echo "  wpscan --url https://example.com --api-token YOUR_TOKEN --enumerate vp,vt,u"
echo ""
echo "To verify installation:"
echo "  wpscan --help"
