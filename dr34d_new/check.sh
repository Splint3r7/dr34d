#!/bin/bash
while read url
do
    urlstatus=$(curl -o /dev/null --silent --head --write-out '%{http_code}' "$url" )
    echo "$url  $urlstatus" >> $1-status-urls.txt
done < $1
