#!/bin/bash
while read p; do
        host $p | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' |awk 'NR==1{print $1; exit}' > resolved-hosts-$1
        while read i; do
                for i in $(cat resolved-hosts-$1); do echo -e "\n[+]Running Masscan on Host: ${p}"; done
                echo "[+] $p : $i" > masscan-all-ports-$1
                masscan $i -p0-1000 --max-rate 1000 >> masscan-all-ports-$1
                IPort=$(cat masscan-all-ports-$1 | cut -d "/" -f1 |cut -d " " -f4 | awk 'BEGIN{OFS=","} FNR==1{first=$0;next} {val=val?val OFS $0:$0} END{print first FS "-p" FS val}')
                echo -e "[+] $p : $i\n" >> $1-nmap.txt
                nmap -sV ${IPort} -Pn -T5 >> $1-nmap.txt
                echo "-----------------------------------" >> $1-nmap.txt
        done < resolved-hosts-$1
done < $1