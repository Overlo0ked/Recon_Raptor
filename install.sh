#!/bin/bash
# Enhanced ReconRaptor Pro Installation
sudo apt update && sudo apt upgrade -y
sudo apt install -y golang python3-pip git npm jq hydra sqlmap ruby gem libcurl4-openssl-dev

# Install advanced tools
go install -v github.com/cgboal/sonarsearch/cmd/crobat@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/gitleaks/v8/cmd/gitleaks@latest
sudo gem install wpscan
sudo apt install -y joomscan droopescan
pip3 install magereport

# Install cloud tools
git clone https://github.com/duo-labs/cloudmapper /opt/cloudmapper
cd /opt/cloudmapper && pip3 install -r requirements.txt

# Setup gitleaks
gitleaks detect --sample-config > /opt/gitleaks-config.toml

# ... rest of installation ...
#!/bin/bash
# ReconRaptor Installation Script
sudo apt update && sudo apt upgrade -y
sudo apt install -y golang python3-pip git npm jq hydra sqlmap

# Install core tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/tomnomnom/assetfinder@latest
sudo wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain
sudo chmod +x /usr/local/bin/findomain
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/hakluke/hakrawler@latest
git clone https://github.com/GerbenJavado/LinkFinder /opt/LinkFinder
cd /opt/LinkFinder && pip3 install -r requirements.txt
git clone https://github.com/m4ll0k/SecretFinder /opt/SecretFinder
cd /opt/SecretFinder && pip3 install -r requirements.txt
sudo wget https://github.com/sensepost/gowitness/releases/latest/download/gowitness-linux-amd64 -O /usr/local/bin/gowitness
sudo chmod +x /usr/local/bin/gowitness
git clone https://github.com/maurosoria/dirsearch /opt/dirsearch
pip3 install dirsearch
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Setup GF patterns
mkdir -p ~/.gf
git clone https://github.com/tomnomnom/gf /opt/gf
cp /opt/gf/examples/* ~/.gf

# Install wordlists
sudo git clone https://github.com/danielmiessler/SecLists /usr/share/wordlists/seclists

# Create ReconRaptor script
cat > reconraptor.sh << 'EOF'
<PASTE THE MAIN SCRIPT HERE>
EOF

chmod +x reconraptor.sh

echo -e "\n[+] Installation complete! Configure Telegram in reconraptor.sh"
echo "[+] Run with: ./reconraptor.sh -d target.com"