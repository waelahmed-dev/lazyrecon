#!/bin/bash

# Invoke with sudo because of dnmasscan

# Config
dirsearchWordlist=./lazyWordLists/altdns_wordlist_small.txt
dirsearchThreads=50

# definitions
enumeratesubdomains(){
  echo "[phase 1] Enumerating all known domains using:"
  echo "subfinder..."
  ../subfinder/subfinder -d $1 -o ./$1/$foldername/subfinder-subdomain-list.txt 
  sleep 5
  sort -u ./$1/$foldername/subfinder-subdomain-list.txt > ./$1/$foldername/1-all-subfinder-subdomain.txt
  sleep 5
}

checkhost(){
  echo "[phase 2] Starting host/DNS live testing..."
  while read subdomain; do
    if host -W 3 -t A "$subdomain" > /dev/null; then
      # If host is live, print it into
      # a file called "host_live.txt".
      echo "$subdomain" >> ./$1/$foldername/2-all-subfinder-subdomain-live.txt
    else
      # need to implement dig here
      echo "${subdomain} unreachable"
      echo "$subdomain" >> ./$1/$foldername/unreachable.txt
    fi
  done < ./$1/$foldername/1-all-subfinder-subdomain.txt
}

permutatesubdomains(){
  if [ ! -e ./$1/$foldername/2-all-subfinder-subdomain-live.txt ]; then
    echo "[checkhost] There is no live servers. Exit 1"
    Exit 1
  fi
  echo "altdns..."
  altdns -i ./$1/$foldername/2-all-subfinder-subdomain-live.txt -o ./$1/$foldername/altdns_output.txt -w $dirsearchWordlist -r -s ./$1/$foldername/99-altdns-live-ip.txt
  sleep 5
  cut -d ':' -f 1 ./$1/$foldername/99-altdns-live-ip.txt > ./$1/$foldername/99-altdns-live.txt
  sort -u ./$1/$foldername/2-all-subfinder-subdomain-live.txt ./$1/$foldername/99-altdns-live.txt > ./$1/$foldername/2-all-subdomain-live.txt
}

checkhttprobe(){
  echo "[phase 3] Starting httprobe testing..."
  cat ./$1/$foldername/2-all-subdomain-live.txt | httprobe > ./$1/$foldername/3-all-subdomain-live-scheme.txt
}

checkmeg(){
  echo "[phase 4] Starting meg sieving on live servers..."
  ../meg/meg -d 10 -c 200 / ./$1/$foldername/3-all-subdomain-live-scheme.txt ./$1/$foldername/megoutput
}

sortliveservers(){
  echo "[phase 5] Sorting hosts..."
  sed -e 's/\http\:\/\///g;s/\https\:\/\///g' ./$1/$foldername/3-all-subdomain-live-scheme.txt | sort -u > ./$1/$foldername/4-all-subdomain-live-sorted.txt
}

avoidredirect(){
  echo "[phase 6] Starting grep on meg output to avoid redirection..."
  cat ./$1/$foldername/4-all-subdomain-live-sorted.txt | while read line;
    do
      for X in ./$1/$foldername/megoutput/${line}/*
        do
          if grep -oE "Location: (http|https)://${line}*" "$X"; then
            head -n 1 "$X" | sed 's/\/$//g' >> ./$1/$foldername/5-live-scheme.txt
          elif ! grep -l "Location:" "$X"; then
            head -n 1 "$X" | sed 's/\/$//g' >> ./$1/$foldername/5-live-scheme.txt
          fi
          if grep -l 'Repository not found\|The specified bucket does not exist\|Github Pages site here\|No such app\|Sorry, this shop is currently unavailable\|404 Blog is not found\|is not a registered InCloud YouTrack' "$X"; then
            cat "$X"
            echo "$line" >> ./$1/$foldername/takeovervulnerable.txt
          fi
        done
    done
  if [ -s ./$1/$foldername/5-live-scheme.txt ]; then
    sed -e 's/\http\:\/\///g;s/\https\:\/\///g' ./$1/$foldername/5-live-scheme.txt | sort -u > ./$1/$foldername/6-live.txt
  else
    "No live hosts found Exit 1"
    exit 1
  fi
  if [ -s ./$1/$foldername/takeovervulnerable.txt ]; then
    printf "${RB_RED}%sPotential Subdomain takeover found under the next hosts:${RESET}"
    echo
    cat ./$1/$foldername/takeovervulnerable.txt
  fi
}

nuclei(){
  nuclei -l ./$1/$foldername/5-live-scheme.txt -t ../nuclei-templates/vulnerabilities/ -t ../nuclei-templates/fuzzing/ -t ../nuclei-templates/security-misconfiguration/ -t /nuclei-templates/cves/ -t /nuclei-templates/misc/ -t ../nuclei-templates/files/ -o 99_nuclei_results.txt
}

checkparams(){
  echo "[phase 7] Get the parameters and paths..."
  cat ./$1/$foldername/6-live.txt | ../gau/gau > ./$1/$foldername/gau_output.txt
  cat ./$1/$foldername/6-live.txt | ../waybackurls/waybackurls > ./$1/$foldername/waybackurls_output.txt
  sort -u ./$1/$foldername/gau_output.txt ./$1/$foldername/waybackurls_output.txt > ./$1/$foldername/params_list.txt
}

# nmap(){
#   echo "[phase 7] Test for unexpected open ports..."
#   nmap -sS -PN -T4 --script='http-title' -oG nmap_output_og.txt  
# }

dnmasscan(){
  echo "[phase 8] Test for unexpected open ports..."
  ../dnmasscan/dnmasscan ./$1/$foldername/6-live.txt ./$1/$foldername/live-ip-list.log -p1-65535 -oG ./$1/$foldername/masscan_output.gnmap --rate 1200
}

brutespray(){
  if [ -s ./$1/$foldername/masscan_output.gnmap ]; then
    echo "[phase 9] Brutespray test..."
    ../brutespray/brutespray.py --file ./$1/$foldername/masscan_output.gnmap
  fi
}

smuggler(){
  echo "[phase NA] Try to find request smuggling vulnerabilities..."
  ../requestsmuggler/smuggler.py -u ./$1/$foldername/5-live-scheme.txt

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
  checkhost $1
  permutatesubdomains $1
  checkhttprobe $1
  checkmeg $1
  sortliveservers $1
  avoidredirect $1
  nuclei $1
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
  mkdir ./$1/$foldername/reports/
  mkdir ./$1/$foldername/megoutput/
  mkdir ./$1/$foldername/dirsearchoutput/
  touch ./$1/$foldername/unreachable.txt

  # touch ./$1/$foldername/takeovervulnerable.txt # do i need this file?

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
