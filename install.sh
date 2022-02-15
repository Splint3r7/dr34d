#sudo apt-get update
#sudo apt-get -y upgrade
#sudo apt-get install git
#sudo apt-get install -y python3-pip
#apt install python-pip
#sudo apt-get install libcurl4-openssl-dev
#sudo apt-get install libssl-dev
#sudo apt-get install jq
#sudo apt-get install ruby-full
#sudo apt-get install masscan
#sudo apt-get install nmap
#apt-get install npm
#sudo apt-get install libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev
#apt-get install docker.io

#Don't forget to set up AWS credentials!
echo "Don't forget to set up AWS credentials!"
apt install awscli
echo "Don't forget to set up AWS credentials!"

sudo apt-get install build-essential libssl-dev libffi-dev python-dev
sudo apt-get install python-setuptools

#create a tools folder in ~/tools/
mkdir ~/tools
cd ~/tools/

echo "installing Sublist3r"
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r*
pip install -r requirements.txt
cd ~/tools/
echo "done"

echo "installing teh_s3_bucketeers"
git clone https://github.com/tomdev/teh_s3_bucketeers.git
cd ~/tools/
echo "done"

echo "installing dirsearch"
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
mkdir wordlists
cd wordlists
wget "https://github.com/danielmiessler/RobotsDisallowed/raw/master/Top100000-RobotsDisallowed.txt"
wget "https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/raft-large-words.txt"
wget "https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/SVNDigger/context/admin.txt"
wget "https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/SVNDigger/cat/Database/sql.txt"
wget "https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/SVNDigger/cat/Database/ini.txt"
cd ~/tools/
echo "done"
#Still need to clone wordlist files!

echo "installing virtual host discovery"
git clone https://github.com/jobertabma/virtual-host-discovery.git
cd ~/tools/
echo "done"

echo "installing knock.py"
sudo apt-get install python-dnspython
git clone https://github.com/guelfoweb/knock.git
cd ~/tools/
echo "done"

echo "installing censys-subdomain-finder"
git clone https://github.com/christophetd/censys-subdomain-finder.git
cd censys-*
pip install -r requirements.txt
cd ~/tools/
echo "[!] Please set your Censys API ID and secret from your environment (CENSYS_API_ID and CENSYS_API_SECRET) in censys-subdomain-finder.py"

echo "installing alive host"
git clone https://github.com/C0RB3N/alive-host.git
cd alive*
chmod +x alive.sh
cd ~/tools/
echo "done"

echo "installing subfinder"
git clone https://github.com/subfinder/subfinder.git
cd subfinder
docker build -t subfinder
docker run -it subfinder


echo "installing jexboss"
git clone https://github.com/joaomatosf/jexboss.git
cd jexboss
pip install -r requires.txt
cd ~/tools/
echo "done"

echo "installing enumall"
git clone https://github.com/jhaddix/domain
cd ~/tools/
echo "done"


echo "Installing Aquatone"
git clone https://github.com/michenriksen/aquatone
cd aqua*
gem install aquatone
aquatone-discover --set-key shodan enter_your_key_here
aquatone-discover --set-key virustotal enter_your_key_here
aquatone-discover --set-key censys_secret enter_your_key_here
aquatone-discover --set-key censys_id enter_your_key_here
cd ~/tools/
echo "done"

#Extra tools that will be intergrated into my script:
git clone https://github.com/jordanpotti/CloudScraper
cd ~/tools/

git clone https://github.com/jobertabma/relative-url-extractor
cd ~/tools/

echo "installing findomain"
mkdir -p ~/tools/Findomain
wget https://github.com/Findomain/Findomain/releases/download/7.0.0-beta.2/findomain-linux
mv findomain-linux ~/tools/ && chmod +x findomain-linux
cd ~/tools/
echo "done"

echo "Installing Amass"
apt-get install amass

echo "Installing Github Search"
cd ~/tools && git clone https://github.com/gwen001/github-search
cd github-search && pip install -r requirements2.txt 

echo -e "\n\n\n\n\n\n\n\n\n\n\nDone! All tools are set up in ~/tools"
ls -la
echo "One last time: don't forget to set up AWS credentials in ~/.aws/!"
