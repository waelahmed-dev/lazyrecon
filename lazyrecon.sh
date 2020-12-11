#!/bin/bash

# Invoke with sudo because of dnmasscan

# Config
dirsearchWordlist=./lazyWordLists/altdns_wordlist_uniq.txt
dirsearchThreads=50

# definitions
enumeratesubdomains(){
  echo "[phase 1] Enumerating all known domains using:"
  echo "subfinder..."
  ../subfinder/subfinder -d $1 -o ./$1/$foldername/subfinder-list.txt
  echo "amass..."
  amass enum -brute -min-for-recursive 3 -d $1 -o ./$1/$foldername/amass-list.txt
}

checkwaybackurls(){
  echo "gau..."
  sort -u ./$1/$foldername/subfinder-list.txt ./$1/$foldername/amass-list.txt > ./$1/$foldername/phase-1-subdomain.txt
  cat ./$1/$foldername/phase-1-subdomain.txt | ../gau/gau -subs -o ./$1/$foldername/99_gau_output.txt
  # gau-list needs for checkparams
  cat ./$1/$foldername/99_gau_output.txt | ../unfurl/unfurl --unique domains > ./$1/$foldername/gau-list.txt
}

sortsubdomains(){
  sort -u ./$1/$foldername/subfinder-list.txt ./$1/$foldername/amass-list.txt ./$1/$foldername/gau-list.txt > ./$1/$foldername/1-real-subdomains.txt
}

permutatesubdomains(){
  if [ ! -e ./$1/$foldername/1-real-subdomains.txt ]; then
    echo "[permutatesubdomains] There is no urls found. Exit 1"
    Exit 1
  fi
  echo "altdns..."
  altdns -i ./$1/$foldername/1-real-subdomains.txt -o ./$1/$foldername/99_altdns_output.txt -w $dirsearchWordlist
  sort -u ./$1/$foldername/1-real-subdomains.txt ./$1/$foldername/99_altdns_output.txt > ./$1/$foldername/2-all-subdomains.txt
}

checkhttprobe(){
  echo "[phase 2] Starting httpx probe testing..."
  httpx -l ./$1/$foldername/2-all-subdomains.txt -silent -follow-host-redirects -fc 301,403,404,503 -o ./$1/$foldername/3-all-subdomain-live-scheme.txt
}

nucleitest(){
  if [ ! -e ./$1/$foldername/3-all-subdomain-live-scheme.txt ]; then
    echo "[nuclei] There is no live hosts. Exit 1"
    Exit 1
  fi
  echo "[phase 3] nuclei testing..."
  nuclei -l ./$1/$foldername/3-all-subdomain-live-scheme.txt -t ../nuclei-templates/generic-detections/ -t ../nuclei-templates/vulnerabilities/ -t ../nuclei-templates/security-misconfiguration/ -t ../nuclei-templates/cves/ -t ../nuclei-templates/misc/ -t ../nuclei-templates/files/ -o ./$1/$foldername/99_nuclei_results.txt
}

sortliveservers(){
  echo "[phase 4] Sorting live hosts..."
  if [ -s ./$1/$foldername/3-all-subdomain-live-scheme.txt ]; then
    sed -e 's/\http\:\/\///g;s/\https\:\/\///g' ./$1/$foldername/3-all-subdomain-live-scheme.txt | sort -u > ./$1/$foldername/4-live.txt
  else
    echo "[sortliveservers] No live hosts found Exit 1"
    exit 1
  fi
}

# nmap(){
#   echo "[phase 7] Test for unexpected open ports..."
#   nmap -sS -PN -T4 --script='http-title' -oG nmap_output_og.txt  
# }
dnmasscan(){
  echo "[phase 5] Test for unexpected open ports..."
  ../dnmasscan/dnmasscan ./$1/$foldername/4-live.txt ./$1/$foldername/live-ip-list.log -p1-65535 -oG ./$1/$foldername/masscan_output.gnmap --rate 1200
}

brutespray(){
  if [ -s ./$1/$foldername/masscan_output.gnmap ]; then
    echo "[phase 6] Brutespray test..."
    ../brutespray/brutespray.py --file ./$1/$foldername/masscan_output.gnmap
  fi
}

smuggler(){
  echo "[phase 7] Try to find request smuggling vulnerabilities..."
  ../requestsmuggler/smuggler.py -u ./$1/$foldername/3-all-subdomain-live-scheme.txt

  # check for VULNURABLE keyword
  if [ -s ./smuggler/output ]; then
    cat ./smuggler/output | grep 'VULNERABLE' > ./$1/$foldername/smugglinghosts.txt
    if [ -s ./$1/$foldername/smugglinghosts.txt ]; then
      printf "${RB_RED}%sSmuggling vulnerability found under the next hosts:${RESET}"
      echo
      cat ./$1/$foldername/smugglinghosts.txt | grep 'VULN'
    else
      echo "There are no Request Smuggling host found"
    fi
  else
    echo "smuggler doesn't provide the output, check it issue!"
  fi
}

# prepare custom wordlist for directory bruteforce
checkparams(){
  echo "gau..."
  cat ./$1/$foldername/1-all-subdomain.txt | ../gau/gau -subs | ../unfurl/unfurl --unique domains > ./$1/$foldername/gau_output.txt
  echo "waybackurls..."
  cat ./$1/$foldername/4-live.txt | ../waybackurls/waybackurls > ./$1/$foldername/waybackurls_output.txt
  sort -u ./$1/$foldername/gau_output.txt ./$1/$foldername/waybackurls_output.txt > ./$1/$foldername/params_list.txt
}

dirsearch(){
  if [ -s ./$1/$foldername/live-list-scheme.txt ]; then
    echo "[phase NA] Start directory bruteforce..."
    ../dirsearch/dirsearch.py -L ./$1/$foldername/live-list-scheme.txt -r -R 2 -e php,asp,aspx,jsp,html,zip,jar,sql,log,txt,js,sh -w $dirsearchWordlist -t $dirsearchThreads --plain-text-report=./$1/$foldername/dirsearchoutput/dirsearchreport.txt
  else
    echo "There are no live host found, so shut down with exit 1."
    Exit 1
  fi
}
ffuf(){
  if [ -s ./$1/$foldername/live-list-scheme.txt ]; then
    echo "[phase NA] Start directory bruteforce..."
    ../ffuf/ffuf.py -L ./$1/$foldername/live-list-scheme.txt -r -R 2 -e php,asp,aspx,jsp,html,zip,jar,sql,log,txt,js,sh -w $dirsearchWordlist -t $dirsearchThreads -o ./$1/$foldername/ffufoutput.txt
  else
    echo "There are no live host found, so shut down with exit 1."
    Exit 1
  fi
}

recon(){
  enumeratesubdomains $1
  checkwaybackurls $1
  sortsubdomains $1
  permutatesubdomains $1
  checkhttprobe $1
  nucleitest $1
  sortliveservers $1
  # checkparams $1
  dnmasscan $1
  brutespray $1

  smuggler $1
  # dirsearch $1
  # ffuf $1

  echo "Generating HTML-report here..."
  echo "Lazy done."
}


main(){
  if [ -d "./$1" ]
  then
    echo "This is a known target."
  else
    mkdir ./$1
  fi
  if [ -s ./smuggler/output ]; then
    rm ./smuggler/output
  fi

  mkdir ./$1/$foldername
  # subfinder list of subdomains
  touch ./$1/$foldername/subfinder-list.txt 
  # amass list of subdomains
  touch ./$1/$foldername/amass-list.txt
  # gau list of subdomains
  touch ./$1/$foldername/gau-list.txt
  # mkdir ./$1/$foldername/reports/
  # mkdir ./$1/$foldername/dirsearchoutput/

  echo "Reports goes to: ./${1}/${foldername}"

    recon $1
    # master_report $1
}

if [[ -z $@ ]]; then
  echo "Error: no targets specified."
  echo "Usage: ./lazyrecon.sh <target>"
  exit 1
fi

./logo.sh
path=$(pwd)
# to avoid cleanup or `sort -u` operation
foldername=recon-$(date +"%y-%m-%d_%H-%M-%S")
main $1
