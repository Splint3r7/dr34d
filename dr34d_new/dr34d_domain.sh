RED='\033[0;31m'
BWhite='\033[1;37m'
GREEN="\033[0;32m"
RESET="\033[0m"
NC='\033[0m'
YELLO="\033[0;33m"
Purple='\033[0;35m'
IRed='\033[0;91m' 
Cyan='\033[0;36m'

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
	python ~/tools/Sublist3r/sublist3r.py -v -t 15 -d $IP -o $IP-sublist3r.txt
	#Install commands to be added in installation script
}
ENUMALL(){
	python ~/tools/domain/enumall.py $IP
	#Install commands to be added in installation script
}
KNOCKPY(){
	python ~/tools/knock/knockpy/knockpy.py -c $IP
#	Install commands to be added in installation script
}
CENSYS(){
	python ~/tools/censys-subdomain-finder/censys_subdomain_finder.py $IP -o $IP-censys.txt
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

## subdomains
DOMAIN-SCAN(){
	QUOTES
	SUBFINDER
	CERTDOMAINFINDER
	DELATOR
	GETALTNAME
	SUBDOMAINNIZER
	#IP=$2
	SUBLIST3R
	sleep 2
	ENUMALL
	sleep 2
	#KNOCKPY
	CENSYS
	sleep 2
	#AQUATONE
	mkdir -p /root/tools/dr34d/Output/compare/
	mkdir -p Output/$folder
	cat /root/aquatone/$IP/hosts.txt |cut -d "," -f1 > $IP-aquatone.txt
	cat $IP.csv|cut -d "," -f1|cut -d "\"" -f2 > $IP.csv
	mv $IP-censys.txt $IP.lst $IP-sublist3r.txt $IP.csv $IP-aquatone.txt Output/$folder
	mv $IP-certdomainfinder.txt $IP-delator.txt $IP-getaltname.txt $IP-subdomainizer.txt $IP-subfinder.txt Output/$folder
	mv /root/aquatone/$IP/$IP-aquatone.txt /root/tools/dr34d/Output/$folder
	cd ~/tools/dr34d/Output/$folder
	cat $IP-censys.txt $IP.lst $IP-sublist3r.txt $IP.csv $IP-aquatone.txt $IP-certdomainfinder.txt $IP-delator.txt $IP-getaltname.txt $IP-subdomainizer.txt $IP-subfinder.txt |sort |uniq > $IP-all-subs
	#cat $IP-certdomainfinder.txt $IP-delator.txt $IP-getaltname.txt $IP-subdomainizer.txt $IP-subfinder.txt |sort |uniq > $IP-all-subs
	rm -rf $IP-censys.txt $IP.lst $IP-sublist3r.txt $IP.csv $IP-aquatone.txt $IP-certdomainfinder.txt $IP-delator.txt $IP-getaltname.txt $IP-subdomainizer.txt $IP-subfinder.txt
	#rm -rf $IP-certdomainfinder.txt $IP-delator.txt $IP-getaltname.txt $IP-subdomainizer.txt $IP-subfinder.txt
	count=$(wc -l $IP-all-subs)
	#cd ~/tools/dr34d
	echo -e "\n${YELLO}[NOTE] ${RED}${count}${NC} Subdomains are ready to test!${NC}"
}

if [[ $1 == "-dc" ]] || [[ $1 == "--domainc" ]]; then
	IP=$2
	folder=$3
	DOMAIN-SCAN
	exit 1
fi

#cd ~/tools/dr34d/
#while read urls; do bash dr34d_domain.sh -dc $urls test_compare; done < domains.txt
#bash dr34d_compare.sh $1 $2

#run like
#bash domain_compare.sh walmart.txt all.txt

