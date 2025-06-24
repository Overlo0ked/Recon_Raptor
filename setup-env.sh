#!/bin/bash
# ReconRaptor Environment Setup

# Load config
CONFIG_FILE="/home/reconraptor/.reconraptor.conf"
if [ -f "$CONFIG_FILE" ]; then
  source "$CONFIG_FILE"
else
  echo "Config file not found! Run install.sh first"
  exit 1
fi

# Configure GF Patterns
sudo -u reconraptor -i bash << 'EOF'
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
EOF

# Install Nuclei Templates
sudo -u reconraptor -i bash << 'EOF'
mkdir -p ~/nuclei-templates
git clone https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates
nuclei -update-templates
EOF

# Setup Telegram webhook (if enabled)
if [ "$TELEGRAM" = true ]; then
  curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/setWebhook" \
    -d url="https://your-server.com/webhook" \
    -d drop_pending_updates=true
fi

echo "Environment setup complete!"