#!/bin/bash
# ReconRaptor Ultimate Installer
# Run: bash <(curl -s https://raw.githubusercontent.com/your/repo/main/install.sh)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Banner
echo -e "${GREEN}"
cat << "EOF"
  ____  _____  ___  ____  ____  _____  ____  ____  
 |  _ \|___ / / _ \|  _ \|  _ \|___ / / ___||  _ \ 
 | |_) | |_ \| | | | |_) | |_) | |_ \| |  _ | |_) |
 |  _ < ___) | |_| |  _ <|  __/ ___) | |_| ||  _ < 
 |_| \_\____/ \___/|_| \_\_|   |____/ \____||_| \_\
EOF
echo -e "${NC}"

# Check root
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[!] This script must be run as root${NC}"
  exit 1
fi

# Create reconraptor user
if ! id "reconraptor" &>/dev/null; then
  echo -e "${YELLOW}[+] Creating dedicated user...${NC}"
  useradd -m -s /bin/bash reconraptor
  usermod -aG sudo reconraptor
  echo "reconraptor ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
fi

# Install dependencies
echo -e "${YELLOW}[+] Installing system dependencies...${NC}"
apt update && apt install -y \
  git python3 python3-pip python3-venv golang jq \
  npm libcurl4-openssl-dev libssl-dev libxml2 libxml2-dev \
  libxslt1-dev build-essential zlib1g-dev

# Install Go tools as reconraptor
echo -e "${YELLOW}[+] Installing Go tools...${NC}"
sudo -u reconraptor -i bash << 'EOF'
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

go install -v github.com/projectdiscovery/{subfinder,httpx,nuclei,naabu,dnsx}@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/tomnomnom/{waybackurls,anew,unfurl,fff,gowitness}@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/shenwei356/rush@latest
go install -v github.com/tomnomnom/qsreplace@latest
go install -v github.com/detectify/page-fetch@latest
EOF

# Clone repositories
echo -e "${YELLOW}[+] Cloning tools...${NC}"
sudo -u reconraptor -i bash << 'EOF'
cd ~
git clone https://github.com/m4ll0k/SecretFinder.git tools/SecretFinder
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
pip3 install -r tools/SecretFinder/requirements.txt

# Install findomain
curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux
mv findomain-linux ~/go/bin/findomain
EOF

# Download main script
echo -e "${YELLOW}[+] Installing ReconRaptor...${NC}"
wget -O /home/reconraptor/reconraptor.sh \
  https://raw.githubusercontent.com/your/repo/main/reconraptor.sh
chmod +x /home/reconraptor/reconraptor.sh

# Create config file
echo -e "${YELLOW}[+] Creating config...${NC}"
sudo -u reconraptor -i bash << 'EOF'
cat > ~/.reconraptor.conf << 'CONFIG'
# ReconRaptor Configuration
TELEGRAM=false
BOT_TOKEN="your_bot_token"
CHAT_ID="your_chat_id"
LHOST="your_server.com"
THREADS=50
WORKDIR_BASE="/home/reconraptor/results"
CONFIG
EOF

# Set permissions
chown -R reconraptor:reconraptor /home/reconraptor

echo -e "${GREEN}[✓] Installation complete!${NC}"
echo -e "\nNext steps:"
echo -e "1. Edit config: nano /home/reconraptor/.reconraptor.conf"
echo -e "2. Test scanner: sudo -u reconraptor ./reconraptor.sh example.com"