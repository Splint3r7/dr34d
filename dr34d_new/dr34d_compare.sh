#!/bin/bash
#OLD fil directory (comapre)
#New file directory (walmart_compare)
cd /root/tools/dr34d/Output/walmart_compare/
cat * >> $2
diff /root/tools/dr34d/Output/compare/$1 /root/tools/dr34d/Output/walmart_compare/$2
rm -rf /root/tools/dr34d/Output/compare/$1 #Deleting old file
mv /root/tools/dr34d/Output/walmart_compare/$2 /root/tools/dr34d/Output/compare/ #Placing new file in old files directory




#!/bin/bash
while read domain; do
        echo -e "${domain}"
        
        wget -qO- "http://web.archive.org/cdx/search/cdx?url=${domain}/*&output=plain&fl=original&collapse=urlkey&filter=statuscode:200" | grep -v "\.jpg" | grep -v "\.png" | grep -v "\.ttf" | grep -v "\.gif" | grep -v "\.jpeg" | grep -v "\.eot" | grep -v "\.woff" | grep -v "\.gif" | grep -v "\.svg" | grep -v "\.htc" | grep -v "\.ico" | sort -u 
        
        curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2020-05-index?url=${domain}/*&output=json" | jq -r .url |sort -u >> 
        

        curl -s --request GET --url "https://www.virustotal.com/vtapi/v2/domain/report?apikey=66725dde43656c331e1160295f3769eff10d675d91e3b1913e101223aff5818a&domain=${domain}" | jq --raw-output -r '.undetected_urls[]? | .[]'|grep 'http' >> 

        curl -s --url "https://otx.alienvault.com/api/v1/indicators/hostname/${domain}/url_list?page=00" | jq -r . | grep "\"url\"" | awk '{print $2}' | cut -d "\"" -f2 | sort -u

        sleep 20
      
done < $1
