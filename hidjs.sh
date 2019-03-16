#Synopsis:
#Get all the old archive urls
#Exract the js files
#Run jsparses on all of the urls
#Save results in singel file
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#!/bin/bash
if [[ $1 == '-wju' ]]; then
	dom=$2
	echo "[+] Running Dread"	
	bash /root/tools/dr34d/dr34d.sh -w $dom
	echo "[+] Exracting all the js files"
	cat /root/tools/dr34d/Ouput/$dom/wayback-output/$dom-wayback-$(date +"%Y-%m-%d").txt | grep ".js" > $dom-js.txt
	echo "[+] Done." 
fi