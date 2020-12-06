#!/bin/bash
IP=$1
wget -qO- "http://web.archive.org/cdx/search/cdx?url=${IP}/*&output=json&fl=original&collapse=urlkey&filter=statuscode:200" |sort |uniq |cut -d "'" -f2|cut -d "\"" -f2 >> out.txt
