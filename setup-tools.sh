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
sudo apt install -y ruby-full ruby-bundler zlib1g-dev || sudo apt install -y ruby-full zlib1g-dev
command -v bundle &> /dev/null || sudo gem install bundler

echo ""
echo "Installing WPScan..."
if [ ! -d "/opt/wpscan" ]; then
    sudo git clone https://github.com/wpscanteam/wpscan.git /opt/wpscan
    (
        cd /opt/wpscan
        sudo bundle install --without test
        sudo ln -sf /opt/wpscan/wpscan.rb /usr/local/bin/wpscan
    )
    echo "WPScan installed successfully!"
else
    echo "WPScan already exists at /opt/wpscan"
fi

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
