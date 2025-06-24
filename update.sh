#!/bin/bash
# ReconRaptor Update Script

echo -e "[*] Updating ReconRaptor..."
cd /home/reconraptor

# Update core tools
sudo -u reconraptor -i bash << 'EOF'
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

go install -v github.com/projectdiscovery/{subfinder,httpx,nuclei}@latest
go install -v github.com/hahwul/dalfox/v2@latest
nuclei -update-templates
EOF

# Update main script
wget -O reconraptor.sh \
  https://raw.githubusercontent.com/your/repo/main/reconraptor.sh
chmod +x reconraptor.sh

echo -e "[✓] Update complete!"