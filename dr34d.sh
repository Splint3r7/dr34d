#!/bin/bash
mainlogo(){
	#Becuse logo is must. Looks Huge? Right :P
	echo -e """${GREEN}
                                                                                                 
DDDDDDDDDDDDD      RRRRRRRRRRRRRRRRR    333333333333333          444444444  DDDDDDDDDDDDD        
D::::::::::::DDD   R::::::::::::::::R  3:::::::::::::::33       4::::::::4  D::::::::::::DDD     
D:::::::::::::::DD R::::::RRRRRR:::::R 3::::::33333::::::3     4:::::::::4  D:::::::::::::::DD   
DDD:::::DDDDD:::::DRR:::::R     R:::::R3333333     3:::::3    4::::44::::4  DDD:::::DDDDD:::::D  
  D:::::D    D:::::D R::::R     R:::::R            3:::::3   4::::4 4::::4    D:::::D    D:::::D 
  D:::::D     D:::::DR::::R     R:::::R            3:::::3  4::::4  4::::4    D:::::D     D:::::D
  D:::::D     D:::::DR::::RRRRRR:::::R     33333333:::::3  4::::4   4::::4    D:::::D     D:::::D
  D:::::D     D:::::DR:::::::::::::RR      3:::::::::::3  4::::444444::::444  D:::::D     D:::::D
  D:::::D     D:::::DR::::RRRRRR:::::R     33333333:::::3 4::::::::::::::::4  D:::::D     D:::::D
  D:::::D     D:::::DR::::R     R:::::R            3:::::34444444444:::::444  D:::::D     D:::::D
  D:::::D     D:::::DR::::R     R:::::R            3:::::3          4::::4    D:::::D     D:::::D
  D:::::D    D:::::D R::::R     R:::::R            3:::::3          4::::4    D:::::D    D:::::D 
DDD:::::DDDDD:::::DRR:::::R     R:::::R3333333     3:::::3          4::::4  DDD:::::DDDDD:::::D  
D:::::::::::::::DD R::::::R     R:::::R3::::::33333::::::3        44::::::44D:::::::::::::::DD   
D::::::::::::DDD   R::::::R     R:::::R3:::::::::::::::33         4::::::::4D::::::::::::DDD     
DDDDDDDDDDDDD      RRRRRRRR     RRRRRRR 333333333333333           4444444444DDDDDDDDDDDDD${NC}        
                                                                                                 	
	~ Dread (DR34D) - Information Gathering and Recon Script ~
		~ Coded By ~
	  					                                            
		|_| _. _ _ _.._ |/|_  _.._\_/   _  _|__  _.o 
		| |(_|_>_>(_|| ||\| |(_|| |||_|_>|_|| /_(_|| 

	"""
}

if [[ $1 == '-h' ]] || [[ $1 == '--help' ]]; then
	echo "[+] Installation:  ./dr34d.sh --install"
	echo "[+] Useage:	./dr34d.sh -d <target> 	[Domain Scan]"
	echo "[+] Useage:	./dr34d.sh -n <target>	[Nmap Scan]"
	echo "[+] Useage:	./dr34d.sh -t <target>	[Comming Soon! :D]"
	echo "[+] Useage:   ./dr34d.sh -w <target> 	[Wayback URL's]"
	echo "[+] Useage: ./dr34d.sh [IP Tools]"
	exit 1
fi

if [[ $1 == '--install' ]] || [[ $1 == '-i' ]]; then
	echo "[+] Installing Dr34d"
	chmod +x install.sh
	./install.sh
	exit 1
fi

QUOTES(){
QUOTES=(
	"Activating 1337 mode!"
	"Never underestimate the determination of a kid who is time-rich and cash-poor."
    "Human Stupidity , that’s why Hackers always win."
    "Hacking is less about technology for me and more about religion."
    "Never tell everything you know…!"
	"Never gonna give you up."
	"Bounty pls."
	"Cyber Security Asli ha"
	"Sleep is for the weak."
	"Haxor 1337 Detected"
	"Grab a cuppa!"
	"I am talking about the guys that no one knows about."
	"I am 100 percent natural."
	"A bug is never just a mistake. It represents something bigger. An error of thinking that makes you who you are."
	"You hack people. I hack time."
	"I hope you don't screw like you type."
	"Hack the planet!"
    "Cyber Security Asli ha"
    "Happy Hunting!"
    "The Quiter you become the more you are able to hear"
    "yeyy, I earned $1500 for my submisson on @H1 & @BugCrowd. xD"
)

rand=$[RANDOM % ${#QUOTES[@]}]
printf "${YELLO}[i]${NC} ${QUOTES[$rand]}\\n"
echo
}

RED='\033[0;31m'
BWhite='\033[1;37m'
GREEN="\033[0;32m"
RESET="\033[0m"
NC='\033[0m'
YELLO="\033[0;33m"
Purple='\033[0;35m'
IRed='\033[0;91m' 
Cyan='\033[0;36m'

GithubSearchSubdomsOut=GithubSearchSubdomsOut.txt
GithubSearchEndpointsOut=GithubSearchEndpointsOut.txt
finddomainOut=finddomainOut.txt
amassOut=amassOut.txt
ScillaOut=ScillaOut.txt

NMAP (){

	echo -e "${YELLO}------------------------------------------------${NC}"
	echo -e "${YELLO}[+] Running Nmap Scan${NC}"
	echo -e "${YELLO}------------------------------------------------${NC}"
	nmap -sV -sC -o $IP-nmap.txt $IP -Pn 
	nmap --script=http-enum -p 80,443,8080 -o $IP-nmap.txt $IP -Pn
	echo -e "${Purple}\n[*] Finished Nmap${NC}"
}

NIKTO (){
	
	echo -e "${YELLO}------------------------------------------------${NC}"
	echo -e "${YELLO}[+] Starting Nikto Scan${NC}"
	echo -e "${YELLO}------------------------------------------------${NC}"
	nikto -h $IP -output=$IP-nikto.txt
	echo -e "${Purple}\n[*] Finished Nikto Scan${NC}"
	
}

MASSCAN (){
	
	echo -e "${YELLO}------------------------------------------------${NC}"
	echo -e "${YELLO}[+] Starting Masscan${NC}"
	echo -e "${YELLO}------------------------------------------------${NC}"
	masscan $IP -p0-65535 --max-rate 1000 -oG $IP-masscan.txt
	echo -e "${Purple}\n[*] Finished Masscan${NC}"

}

DIRSEARCH (){
	
	echo -e "${YELLO}------------------------------------------------${NC}"
	echo -e "${YELLO}[+] Starting Dirsearch Scan${NC}"
	echo -e "${YELLO}------------------------------------------------${NC}"
	python3 ~/tools/dirsearch/dirsearch.py -u $IP -e php,asp,aspx,jsp,js,ini,html,log,txt,sql,zip,conf,cgi,json,jar,dll,xml --plain-text-report=$IP-dirsearch.txt
	sleep 3
	python3 ~/tools/dirsearch/dirsearch.py -u $IP -e php,asp,aspx,jsp,js,ini,html,log,txt,sql,zip,conf,cgi,json,jar,dll,xml -w ~/tools/dirsearch/wordlists/raft-large-words.txt --plain-text-report=$IP-dirsearch1.txt
	sleep 3
	python3 ~/tools/dirsearch/dirsearch.py -u $IP -e php,asp,aspx,jsp,js,ini,html,log,txt,sql,zip,conf,cgi,json,jar,dll,xml -w ~/tools/dirsearch/wordlists/Top100000-RobotsDisallowed.txt --plain-text-report=$IP-dirsearch2.txt
	sleep 3
	echo -e "$${Purple}\n[*] Finished Dirsearch Scan${NC}"

}

#Part-3# Beg Bounties
CERTDOMAINFINDER(){
	~/tools/certdomainfinder $IP >> $IP-certdomainfinder.txt
}
DELATOR(){
	~/tools/delator -d $IP >> $IP-delator.txt
}
GETALTNAME(){
	python3 ~/tools/getaltname-1.0.0/getaltname.py -s -m $IP -o $IP-getaltname.txt 
}
SUBDOMAINNIZER(){
	python3 ~/tools/SubDomainizer/SubDomainizer.py -u $IP -o $IP-subdomainizer.txt
}
SUBFINDER(){
	~/tools/subfinder -d $IP -o $IP-subfinder.txt
}
SUBLIST3R(){
	python3 ~/tools/Sublist3r/sublist3r.py -v -t 15 -d $IP -o $IP-sublist3r.txt
	#Install commands to be added in installation script
}
ENUMALL(){
	python2 ~/tools/domain/enumall.py $IP
	#Install commands to be added in installation script
}
KNOCKPY(){
	python2 ~/tools/knock/knockpy/knockpy.py -c $IP
#	Install commands to be added in installation script
}
CENSYS(){
	python3 ~/tools/censys-subdomain-finder/censys_subdomain_finder.py $IP -o $IP-censys.txt
	#Don;t forget to add API_KEYS of censys in censys_subdomain_finder.py
}
AQUATONE(){
	aquatone-discover --domain $IP
}

ALIVE-HOST (){
	bash ~/tools/alive-host/alive.sh All-Subdomains.txt
}

JEXBOSS (){
	echo -e "${YELLO}------------------------------------------------${NC}"
	echo -e "${YELLO}[+] Starting Jexboss Scan${NC}"
	echo -e "${YELLO}------------------------------------------------${NC}"
	python ~/tools/jexboss/jexboss.py -u $IP
	echo -e "${Purple}\n[*] Finished Jexboss${NC}"
}

AMASS() {
	amass enum -active -o $amassOut -d $IP
}

FINDOMAIN () {
	~/tools/Findomain/findomain-linux -t $IP -u $finddomainOut
}

GithubDomains () {
	echo "[+] GithubSearch Domain Scan Running...."
	python3 ~/tools/github-search/github-subdomains.py -t "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" -d $IP >> $GithubSearchSubdomsOut
}

Scilla () {
	scilla subdomain -target target.domain -o $ScillaOut
}

## subdomains
DOMAIN-SCAN(){
	QUOTES
	FINDOMAIN
	SUBFINDER
	GithubDomains
	AMASS
	Scilla
	CERTDOMAINFINDER
	DELATOR
	GETALTNAME
	SUBDOMAINNIZER
	#IP=$2
	SUBLIST3R
	sleep 2
	ENUMALL
	sleep 2
	CENSYS
	sleep 2
	mkdir -p Output/$IP/$IP-domains
	cat /root/aquatone/$IP/hosts.txt |cut -d "," -f1 > $IP-aquatone.txt
	cat $IP.csv|cut -d "," -f1|cut -d "\"" -f2 > $IP.csv
	mv $IP-censys.txt $IP.lst $IP-sublist3r.txt $ScillaOut $GithubSearchSubdomsOut $amassOut $finddomainOut $IP.csv $IP-aquatone.txt Output/$IP/$IP-domains
	mv $IP-certdomainfinder.txt $IP-delator.txt $IP-getaltname.txt $IP-subdomainizer.txt $IP-subfinder.txt Output/$IP/$IP-domains
	mv /root/aquatone/$IP/$IP-aquatone.txt /root/tools/dr34d/$IP-201*
	cd ~/tools/dr34d/Output/$IP/$IP-domains
	cat $IP-censys.txt $IP.lst $IP-sublist3r.txt $GithubSearchSubdomsOut $ScillaOut $finddomainOut $amassOut $IP.csv $IP-aquatone.txt $IP-certdomainfinder.txt $IP-delator.txt $IP-getaltname.txt $IP-subdomainizer.txt $IP-subfinder.txt |sort |uniq > $IP-all-subs
	#cat $IP-certdomainfinder.txt $IP-delator.txt $IP-getaltname.txt $IP-subdomainizer.txt $IP-subfinder.txt |sort |uniq > $IP-all-subs
	rm -rf $IP-censys.txt $IP.lst $IP-sublist3r.txt $GithubSearchSubdomsOut $ScillaOut $finddomainOut $amassOut $IP.csv $IP-aquatone.txt $IP-certdomainfinder.txt $IP-delator.txt $IP-getaltname.txt $IP-subdomainizer.txt $IP-subfinder.txt
	#rm -rf $IP-certdomainfinder.txt $IP-delator.txt $IP-getaltname.txt $IP-subdomainizer.txt $IP-subfinder.txt
	count=$(wc -l $IP-all-subs)
	#cd ~/tools/dr34d
	echo -e "\n${YELLO}[NOTE] ${RED}${count}${NC} Subdomains are ready to test!${NC}"
}

if [[ $1 == "-d" ]] || [[ $1 == "--domain" ]]; then
	IP=$2
	DOMAIN-SCAN
	exit 1
fi

#bash dr34d.sh -t domain.com
if [[ $1 == "--takeover" ]] || [[ $1 == "-t" ]]; then
	domain=$2
	#cd ~/tools/dr34d/Subtakeover
	echo "[+] Resolving Hosts"
	bash Subtakeover/resolvehosts-json.sh -r $2 Output/$2/$2-domains/$2-all-subs
	sleep 2
	echo "[+] Resolving Hosts in JSON Format"
	python Subtakeover/json-out.py Output/$2/hosts.txt > Output/$2/hosts.json
	sleep 2
	rm -rf /root/aquatone/hassankhanyusufzai.com/hosts.json
	cp Output/$2/hosts.json /root/aquatone/$2/
	echo "[+] Running Aquatone TakeOver"
	aquatone-takeover -d $2
	exit 1
fi

## NMAP
NMAP-LIST(){

	nmap -iL $file -sP -o Output/$IP/NmapOutput/Nmap-Service-Scan
	nmap -iL $file -sP -Pn -o Output/$IP/NmapOutput/Nmap-Enum-Scan
}

if [[ $1 == "--nmap" ]] || [[ $1 = "-n" ]]; then
	#./dr34d.sh -n $foldername $file_path
	IP=$2
	file=Output/$IP/$IP-domains/$2-all-subs
	mkdir -p Output/$IP/NmapOutput
	NMAP-LIST
	exit 1
fi

wayback-logo(){
	echo -e """

WW      WW                 BBBBB                  kk     
WW      WW   aa aa yy   yy BB   B    aa aa   cccc kk  kk 
WW   W  WW  aa aaa yy   yy BBBBBB   aa aaa cc     kkkkk  
 WW WWW WW aa  aaa  yyyyyy BB   BB aa  aaa cc     kk kk  
  WW   WW   aaa aa      yy BBBBBB   aaa aa  ccccc kk  kk 
                    yyyyy                                
	"""
}

WAYBACK(){
	#probably works for domain xD
	wget -qO- "http://web.archive.org/cdx/search/cdx?url=${IP}/*&output=json&fl=original&collapse=urlkey&filter=statuscode:200" |sort |uniq |cut -d "'" -f2|cut -d "\"" -f2 > Output/$IP/wayback-output/$IP-wayback-$(date +"%Y-%m-%d").txt
}
VIRUSTATOL(){
	curl -s --request GET --url "https://www.virustotal.com/vtapi/v2/domain/report?apikey=66725dde43656c331e1160295f3769eff10d675d91e3b1913e101223aff5818a&domain=${IP}"| jq --raw-output -r '.undetected_urls[]? | .[]'|grep 'http' >> Output/$IP/wayback-output/$IP-wayback-$(date +"%Y-%m-%d").txt
}
COMMONCRAWL(){
	curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2017-09-index?url=*.${IP}/*&output=json"|jq -r .url |sort -u >> Output/$IP/wayback-output/$IP-wayback-$(date +"%Y-%m-%d").txt
}
DIRSCRAPPER(){
	#FOR MAC OS
	python /Users/hassankhan/tools/dirscraper/dirscraper.py -u https://${IP} >> Output/$IP/wayback-output/$IP-wayback-$(date +"%Y-%m-%d").txt
	python /Users/hassankhan/tools/dirscraper/dirscraper.py -u ${IP} >> Output/$IP/wayback-output/$IP-wayback-$(date +"%Y-%m-%d").txt
	#Change directory for linux
	#python ~/tools/dirscraper/dirscraper.py -u https://${IP} >> Output/$IP/wayback-output/$IP-wayback-$(date +"%Y-%m-%d").txt
	#python ~/tools/dirscraper/dirscraper.py -u ${IP} >> Output/$IP/wayback-output/$IP-wayback-$(date +"%Y-%m-%d").txt

}

if [[ $1 == '--wayback' ]] || [[ $1 == '-w' ]]; then
	
	wayback-logo
	QUOTES
	IP=$2
	mkdir -p Output/$IP/wayback-output
	WAYBACK
	VIRUSTATOL
	COMMONCRAWL
	DIRSCRAPPER
	count=$(wc -l Output/$IP/wayback-output/${IP}-wayback-$(date +"%Y-%m-%d").txt|cut -d " " -f1)
	echo "${count}"
	echo -e "\n${YELLO}[NOTE] ${RED}[${count}]${NC} Url's are Loaded from $IP-wayback-$(date +"%Y-%m-%d").txt${NC}"
	cat Output/$IP/wayback-output/$IP-wayback-$(date +"%Y-%m-%d").txt
	exit 1

fi

#Part-2# OSINT - Information Gathering
logo2() {
	echo -e """${GREEN}

'####:'########:::::::::::'########::'#######:::'#######::'##::::::::'######::
. ##:: ##.... ##::::::::::... ##..::'##.... ##:'##.... ##: ##:::::::'##... ##:
: ##:: ##:::: ##::::::::::::: ##:::: ##:::: ##: ##:::: ##: ##::::::: ##:::..::
: ##:: ########::'#######:::: ##:::: ##:::: ##: ##:::: ##: ##:::::::. ######::
: ##:: ##.....:::........:::: ##:::: ##:::: ##: ##:::: ##: ##::::::::..... ##:
: ##:: ##:::::::::::::::::::: ##:::: ##:::: ##: ##:::: ##: ##:::::::'##::: ##:
'####: ##:::::::::::::::::::: ##::::. #######::. #######:: ########:. ######::
....::..:::::::::::::::::::::..::::::.......::::.......:::........:::......:::

 	${NC}"""
 }

 OSINT (){
	printf "${GREEN}Enter the [ IP / DOMAIN ]~# ${NC}"
	read Target
}

WHOIS (){
	curl http://api.hackertarget.com/whois/?q=$Target
}

DNSLOOKUP (){
	curl http://api.hackertarget.com/dnslookup/?q=$Target
}

REVERSE-DNS (){
	curl https://api.hackertarget.com/reversedns/?q=$Target
}

GEO-IP (){
	curl http://api.hackertarget.com/geoip/?q=$Target
}

REVERSE-IP (){
	curl http://api.hackertarget.com/reverseiplookup/?q=$Target
}

TRACEOUT (){
	curl https://api.hackertarget.com/mtr/?q=$Target
}

RunAgain (){
	IP-TOOLS
	printf "${IRed}Do you want to run again? ${NC} ${BWhite}[y/n]::${NC}"
	read var
	if [[ $var == [A-Z] && $var == 'y' ]]; then
		clear
		RunAgain
	else
		echo -e "${YELLO}Thank you for using :~)${NC}"
	fi
}

IP-TOOLS() {
	clear
	logo2
	echo -e "\n"
	echo -e "${BWhite}[1] WHOIS LOOKup!"
	echo "[2] DNS LOOK UP"
	echo "[3] Reverse DNS"
	echo "[4] Geo IP"
	echo -e "[5] Reverse IP"
	echo -e "[6] Traceout\n${NC}"
	printf "${RED}Dr34d~#  ${NC}"
	read -r userinp1
	if [[ "$userinp1" = 1 ]]; then
		OSINT
		WHOIS
		echo -e "\n"
	elif [[ "$userinp1" = 2 ]]; then
		OSINT
		DNSLOOKUP
		echo -e "\n"
	elif [[ "$userinp1" = 3 ]]; then
		OSINT
		REVERSE-DNS
		echo -e "\n"
	elif [[ "$userinp1" = 4 ]]; then
		OSINT
		GEO-IP
		echo -e "\n"
	elif [[ "$userinp1" = 5 ]]; then
		OSINT
		REVERSE-IP
		echo -e "\n"
	elif [[ "$userinp1" = 6 ]]; then
		OSINT
		TRACEOUT
		echo -e "\n"
	else
		echo -e "${YELLO}Are you trying to cheat my tool :~/${NC}"
	 fi 
}

HTTPROBE () {
	cat ~/tools/dr34d/Output/$IP/$IP-domains/$IP-all-subs | httprobe -c 200 | tee ../$IP-httprobe.txt
}


SPIDERPOC () {

	DOMAIN-SCAN

	HTTPROBE

}

if [[ $1 == "-p" ]] || [[ $1 == "--poc" ]]; then
	IP=$2
	SPIDERPOC
	exit 1
fi


#Main 
clear
mainlogo
echo -e "[1] OSINT"
printf "${RED}Dr34d~# ${NC}"
read -r userinp

if [[ "$userinp" = 1 ]]; then
	#statements
	RunAgain
	
else
	RunAgain
	echo -e "${IRed}Ops! This tools is still in Beta xD ~${NC}"
fi
