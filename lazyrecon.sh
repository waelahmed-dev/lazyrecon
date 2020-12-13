#!/bin/bash

# Invoke with sudo because of dnmasscan

# Config
altdnsWordlist=./lazyWordLists/altdns_wordlist_uniq.txt
dirsearchWordlist=./lazyWordLists/curated_top100.txt
dirsearchThreads=100

# definitions
enumeratesubdomains(){
  echo "[phase 1] Enumerating all known domains using:"
  echo "subfinder..."
  subfinder -d $1 -recursive -o ./$1/$foldername/subfinder-list.txt
  echo "assetfinder..."
  assetfinder --subs-only $1 > ./$1/$foldername/assetfinder-list.txt
  echo "amass..."
  amass enum -brute -min-for-recursive 4 -d $1 -o ./$1/$foldername/amass-list.txt
  # sort enumerated subdomains
  sort -u ./$1/$foldername/subfinder-list.txt ./$1/$foldername/amass-list.txt ./$1/$foldername/assetfinder-list.txt > ./$1/$foldername/enumerated-subdomains.txt
}

checkwaybackurls(){
  echo "gau..."
  # gau -subs mean include subdomains
  cat ./$1/$foldername/enumerated-subdomains.txt | gau -subs -o ./$1/$foldername/gau_output.txt
  echo "waybackurls..."
  cat ./$1/$foldername/enumerated-subdomains.txt | waybackurls > ./$1/$foldername/waybackurls_output.txt

  # 99_wayback_list needs for checkparams
  sort -u ./$1/$foldername/gau_output.txt ./$1/$foldername/waybackurls_output.txt > ./$1/$foldername/99_wayback_list.txt
  cat ./$1/$foldername/99_wayback_list.txt | unfurl --unique domains > ./$1/$foldername/wayback-list.txt
}

sortsubdomains(){
  sort -u ./$1/$foldername/enumerated-subdomains.txt ./$1/$foldername/wayback-list.txt > ./$1/$foldername/1-real-subdomains.txt
}

permutatesubdomains(){
  if [ ! -e ./$1/$foldername/1-real-subdomains.txt ]; then
    echo "[permutatesubdomains] There is no urls found. Exit 1"
    Exit 1
  fi
  echo "altdns..."
  altdns -i ./$1/$foldername/1-real-subdomains.txt -o ./$1/$foldername/99_altdns_output.txt -w $altdnsWordlist
  sort -u ./$1/$foldername/1-real-subdomains.txt ./$1/$foldername/99_altdns_output.txt > ./$1/$foldername/2-all-subdomains.txt
}

checkhttprobe(){
  echo "[phase 2] Starting httpx probe testing..."
  httpx -l ./$1/$foldername/2-all-subdomains.txt -silent -follow-host-redirects -fc 301,302,403,404,503 -o ./$1/$foldername/3-all-subdomain-live-scheme.txt
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
  sed -e 's/\http\:\/\///g;s/\https\:\/\///g' ./$1/$foldername/3-all-subdomain-live-scheme.txt | sort -u > ./$1/$foldername/4-live.txt
}

# nmap(){
#   echo "[phase 7] Test for unexpected open ports..."
#   nmap -sS -PN -T4 --script='http-title' -oG nmap_output_og.txt  
# }
dnmasscan(){
  echo "[phase 5] Test for unexpected open ports..."
  dnmasscan ./$1/$foldername/4-live.txt ./$1/$foldername/live-ip-list.log -p1-65535 -oG ./$1/$foldername/masscan_output.gnmap --rate 1200
}

brutespray(){
  if [ -s ./$1/$foldername/masscan_output.gnmap ]; then
    echo "[phase 6] Brutespray test..."
    ../brutespray/brutespray.py --file ./$1/$foldername/masscan_output.gnmap
  fi
}

smuggler(){
  echo "[phase 7] Try to find request smuggling vulnerabilities..."
  smuggler.py -u ./$1/$foldername/3-all-subdomain-live-scheme.txt

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
  echo "[phase 8] Prepare custom wordlist using unfurl"
  cat ./$1/$foldername/99_wayback_list.txt | unfurl paths | sed 's/\///' > ./$1/$foldername/101_wayback_params_list.txt
  # merge base dirsearchWordlist with target-specific
  sort -u ./$1/$foldername/101_wayback_params_list.txt $dirsearchWordlist > ./$1/$foldername/101_params_list.txt
}

ffufbrute(){
  echo "[phase 9] Start directory bruteforce..."
  iterator=1
  while read subdomain; do
    iterator=$((iterator+1))
    ffuf -c -u ${subdomain}/FUZZ -sf -mc all -fc 300,301,302,303,304 -recursion -recursion-depth 3 -w ./$1/$foldername/101_params_list.txt -t $dirsearchThreads -o ./$1/$foldername/ffuf/${iterator}.csv -of csv
  done < ./$1/$foldername/3-all-subdomain-live-scheme.txt
}

recon(){
  enumeratesubdomains $1
  checkwaybackurls $1
  sortsubdomains $1
  permutatesubdomains $1
  checkhttprobe $1
  nucleitest $1
  sortliveservers $1
  dnmasscan $1
  brutespray $1
  smuggler $1

  checkparams $1
  ffufbrute $1

  # echo "Generating HTML-report here..."
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
  # ffuf dir uses to store brute output
  mkdir ./$1/$foldername/ffuf/
  # subfinder list of subdomains
  touch ./$1/$foldername/subfinder-list.txt 
  # amass list of subdomains
  touch ./$1/$foldername/amass-list.txt
  # assetfinder list of subdomains
  touch ./$1/$foldername/assetfinder-list.txt
  # gau/waybackurls list of subdomains
  touch ./$1/$foldername/wayback-list.txt
  # gau list of only params
  touch ./$1/$foldername/101_wayback_params_list.txt
  # mkdir ./$1/$foldername/reports/

  echo "Reports goes to: ./${1}/${foldername}"

    recon $1
    # master_report $1
}

usage(){
  echo "Usage: $FUNCNAME \"<target>\""
  echo "Example: $FUNCNAME \"example.com\""
}

invokation(){
  echo "Warn: unexpected positional argument: $1"
  echo "$(basename $0) [[-h] | [--help]]"
}

# check for specifiec arguments (help)
checkhelp(){
  while [ "$1" != "" ]; do
      case $1 in
          -h | --help )           usage
                                  exit
                                  ;;
          # * )                     invokation $1
          #                         exit 1
      esac
      shift
  done
}


##### Main
echo "Check params 1: $@"

if [ $# -eq 1 ]; then
  checkhelp "$@"
# else
#   if [ $# -ne 3 ]; then
#     echo "Error: expected arguments count"
#     usage
#     exit 1
#   fi
fi
if [[ -z $@ ]]; then
  usage
  exit 1
fi

./logo.sh
path=$(pwd)
# to avoid cleanup or `sort -u` operation
foldername=recon-$(date +"%y-%m-%d_%H-%M-%S")

# invoke with asn
main $1