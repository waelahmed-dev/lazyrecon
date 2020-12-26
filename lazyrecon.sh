#!/bin/bash

# Invoke with sudo because of masscan/nmap

# Config
altdnsWordlist=./lazyWordLists/altdns_wordlist_uniq.txt
dirsearchWordlist=./lazyWordLists/curated.txt
miniResolvers=./resolvers/mini_resolvers.txt
madResolvers=./resolvers/resolvers.txt
dirsearchThreads=200

# optional positional arguments
brute= # enable directory bruteforce
mad= # if you sad about subdomains count, call it
alt= # permutate and alterate subdomains
wildcard= # fight against multi-level wildcard DNS to avoid false-positive results while subdomain resolves

# definitions
enumeratesubdomains(){
  echo "Enumerating all known domains using:"

  # Passive subdomain enumeration
  echo "subfinder..."
  subfinder -d $1 -silent -o ./$1/$foldername/subfinder-list.txt
  echo "assetfinder..."
  assetfinder --subs-only $1 > ./$1/$foldername/assetfinder-list.txt
  # echo "amass..."
  # amass enum --passive -log ./$1/$foldername/amass_errors.log -d $1 -o ./$1/$foldername/amass-list.txt

  # sort enumerated subdomains
  sort -u ./$1/$foldername/subfinder-list.txt ./$1/$foldername/amass-list.txt ./$1/$foldername/assetfinder-list.txt -o ./$1/$foldername/enumerated-subdomains.txt
}

checkwaybackurls(){
  if [ "$mad" = "1" ]; then
    echo "gau..."
    # gau -subs mean include subdomains
    cat ./$1/$foldername/enumerated-subdomains.txt | gau -subs -o ./$1/$foldername/gau_output.txt
    echo "waybackurls..."
    cat ./$1/$foldername/enumerated-subdomains.txt | waybackurls > ./$1/$foldername/waybackurls_output.txt

    # wayback_output.txt needs for checkparams
    sort -u ./$1/$foldername/gau_output.txt ./$1/$foldername/waybackurls_output.txt -o ./$1/$foldername/wayback_output.txt
    sed -i '' '/web.archive.org/d' ./$1/$foldername/wayback_output.txt
    cat ./$1/$foldername/wayback_output.txt | unfurl --unique domains > ./$1/$foldername/wayback-subdomains-list.txt
  fi
  if [ "$alt" = "1" -a "$mad" = "1" ]; then
    # prepare target specific subdomains wordlist to gain more subdomains using --mad mode
    cat ./$1/$foldername/wayback_output.txt | unfurl format %S | sort | uniq > ./$1/$foldername/wayback-subdomains-wordlist.txt
    sort -u $altdnsWordlist ./$1/$foldername/wayback-subdomains-wordlist.txt -o $customSubdomainsWordList
  fi
}

sortsubdomains(){
  sort -u ./$1/$foldername/enumerated-subdomains.txt ./$1/$foldername/wayback-subdomains-list.txt -o ./$1/$foldername/1-real-subdomains.txt
  cp ./$1/$foldername/1-real-subdomains.txt ./$1/$foldername/2-all-subdomains.txt
}

permutatesubdomains(){
  if [ "$alt" = "1" ]; then
    echo "altdns..."
    altdns -i ./$1/$foldername/1-real-subdomains.txt -o ./$1/$foldername/altdns_output.txt -w $customSubdomainsWordList

    sort -u ./$1/$foldername/1-real-subdomains.txt ./$1/$foldername/altdns_output.txt -o ./$1/$foldername/2-all-subdomains.txt
  fi
}

# check live subdomains
# wildcard check like: `dig @188.93.60.15 A,CNAME {test123,0000}.$domain +short`
# shuffledns uses for wildcard because massdn can't
dnsprobing(){
  # check file wirteup successfully from previous step
  # while [ ! -s ./$1/$foldername/2-all-subdomains.txt ]; do
  #   echo "[dnsprobing] 2-all-subdomains.txt empty, sleep 1"
  #   sleep 1
  # done
  if [ "$wildcard" = "1" ]; then
    echo "[shuffledns] massdns probing with wildcard sieving..."
    shuffledns -d $1 -list ./$1/$foldername/2-all-subdomains.txt -retries 1 -r $madResolvers -o ./$1/$foldername/shuffledns-list.txt
    # additional resolving because shuffledns missing IP on output
    echo "[dnsx] dnsprobing..."
    # echo "[dnsx] wildcard filtering:"
    # dnsx -l ./$1/$foldername/shuffledns-list.txt -wd $1 -o ./$1/$foldername/dnsprobe_live.txt
    echo "[dnsx] getting hostnames and its A records:"
    dnsx -a -resp -l ./$1/$foldername/shuffledns-list.txt -o ./$1/$foldername/dnsprobe_output_tmp.txt
    # clear file from [ and ] symbols
    tr -d '\[\]' < ./$1/$foldername/dnsprobe_output_tmp.txt > ./$1/$foldername/dnsprobe_output.txt
    # split resolved hosts ans its IP (for masscan)
    # cut -f1 -d ' ' ./$1/$foldername/dnsprobe_output.txt | sort | uniq > ./$1/$foldername/dnsprobe_subdomains.txt
    cut -f2 -d ' ' ./$1/$foldername/dnsprobe_output.txt | sort | uniq > ./$1/$foldername/dnsprobe_ip.txt
  else
    echo "[massdns] dnsprobing..."
    # pure massdns:
    massdns -r $madResolvers -o S -w ./$1/$foldername/massdns_output.txt ./$1/$foldername/2-all-subdomains.txt
    sed -i '' '/CNAME/d' ./$1/$foldername/massdns_output.txt
    # cut -f1 -d ' ' ./$1/$foldername/massdns_output.txt | sed 's/.$//' | sort | uniq > ./$1/$foldername/dnsprobe_subdomains.txt
    cut -f3 -d ' ' ./$1/$foldername/massdns_output.txt | sort | uniq > ./$1/$foldername/dnsprobe_ip.txt
  fi
}

# nmap(){
#   echo "[phase 7] Test for unexpected open ports..."
#   nmap -sS -PN -T4 --script='http-title' -oG nmap_output_og.txt
# }
masscantest(){
  echo "[masscan] Looking for open ports..."
  # max-rate for accuracy
  masscan -p1-65535 -iL ./$1/$foldername/dnsprobe_ip.txt --rate 5000 --open-only -oG ./$1/$foldername/masscan_output.gnmap
}

# scan for specifiec PORTS (21,22,...)
# -Pn: Treat all hosts as online -- skip host discovery
# -sV: Probe open ports to determine service/version info
  #  old approach
  # nmap --script "discovery,ftp*,ssh*,http-vuln*,mysql-vuln*,imap-*,pop3-*" -iL ./$1/$foldername/nmap_input.txt
nmap_nse(){
  echo "[brutespray] Brute known services on open ports..."
  brutespray.py --file ./$1/$foldername/masscan_output.gnmap --threads 5 --hosts 5 -c -o ./$1/$foldername/brutespray_output

  # https://gist.github.com/storenth/b419dc17d2168257b37aa075b7dd3399
  # https://youtu.be/La3iWKRX-tE?t=1200
  # https://medium.com/@noobhax/my-recon-process-dns-enumeration-d0e288f81a8a
  # echo "${RB_VIOLET}${BOLD}[nmap] scanning...${RESET}"
  # while read line; do
  #   IP=$(echo $line | awk '{ print $4 }')
  #   PORT=$(echo $line | awk '{ print $3 }')
  #   FILENAME=$(echo $line | awk -v PORT=$PORT '{ print "nmap_"PORT"_"$4}' )

  #   echo "${RB_VIOLET}[nmap] scanning $IP using $PORT port${RESET}"
  #   nmap -vv -sV --version-intensity 5 -sT -O --max-rate 5000 -Pn -T3 -p$PORT -oG ./$1/$foldername/nmap/$FILENAME $IP
  #   sleep 1
  #   echo "${RB_VIOLET}[brutespray] scanning on $FILENAME${RESET}"
  #   brutespray.py --file ./$1/$foldername/nmap/${FILENAME} --threads 5 -c -o ./$1/$foldername/brutespray/$FILENAME
  # done < ./$1/$foldername/masscan_output_tmp.txt
}

checkhttprobe(){
  echo "[httpx] Starting httpx probe testing..."
  # resolve IP and hosts with http|https for bruteforce
  httpx -silent -l ./$1/$foldername/dnsprobe_ip.txt -silent -follow-host-redirects -fc 300,301,302,303 -threads 300 -o ./$1/$foldername/3-all-subdomain-live-scheme.txt
  # httpx -l ./$1/$foldername/dnsprobe_subdomains.txt -silent -follow-host-redirects -fc 300,301,302,303 -threads 300 -o ./$1/$foldername/httpx_output_2.txt
  # touch ./$1/$foldername/httpx_output_2.txt

  # sort -u ./$1/$foldername/httpx_output_1.txt ./$1/$foldername/httpx_output_2.txt > ./$1/$foldername/3-all-subdomain-live-scheme.txt
}

nucleitest(){
  if [ ! -e ./$1/$foldername/3-all-subdomain-live-scheme.txt ]; then
    echo "[nuclei] There is no live hosts. exit 1"
    exit 1
  fi
  echo "[nuclei] CVE testing..."
  nuclei -l ./$1/$foldername/3-all-subdomain-live-scheme.txt -t ../nuclei-templates/generic-detections/ -t ../nuclei-templates/vulnerabilities/ -t ../nuclei-templates/security-misconfiguration/ -t ../nuclei-templates/cves/ -t ../nuclei-templates/misc/ -t ../nuclei-templates/files/ -t ../nuclei-templates/subdomain-takeover -o ./$1/$foldername/nuclei_output.txt
}

smuggler(){
  echo "[smuggler] Try to find request smuggling vulnerabilities..."
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
    echo "smuggler doesn\'t provide the output, check it issue!"
  fi
}

# prepare custom wordlist for directory bruteforce using --mad and --brute mode only
checkparams(){
  if [ "$brute" = "1" -a "$mad" = "1" ]; then
    echo "Prepare custom wordlist using unfurl"
    cat ./$1/$foldername/wayback_output.txt | unfurl paths | sed 's/\///' > ./$1/$foldername/wayback_params_list.txt
    # merge base dirsearchWordlist with target-specific list for deep dive (time sensitive)
    sort -u ./$1/$foldername/wayback_params_list.txt $dirsearchWordlist -o $customFfufWordList
    sudo sed -i '' '/^[[:space:]]*$/d' $customFfufWordList
  fi
}

ffufbrute(){
  if [ "$brute" = "1" ]; then
    echo "Start directory bruteforce using ffuf..."
    iterator=1
    while read subdomain; do
      ffuf -c -u ${subdomain}/FUZZ -H "referer:${subdomain}/FUZZ" -mc all -fc 300,301,302,303,304,500,501,502,503 -w $customFfufWordList -t $dirsearchThreads -o ./$1/$foldername/ffuf/${iterator}.csv -of csv
      iterator=$((iterator+1))
    done < ./$1/$foldername/3-all-subdomain-live-scheme.txt
  fi
}

recon(){
  enumeratesubdomains $1
  checkwaybackurls $1
  sortsubdomains $1
  permutatesubdomains $1

  dnsprobing $1
  masscantest $1
  nmap_nse $1

  checkhttprobe $1
  nucleitest $1
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

  # used for ffuf bruteforce
  touch ./$1/$foldername/custom_ffuf_wordlist.txt
  customFfufWordList=./$1/$foldername/custom_ffuf_wordlist.txt
  cp $dirsearchWordlist $customFfufWordList
  # used to save target specific list for alterations (shuffledns, altdns)
  # if [ "$mad" = "1" ]; then
  #   altdnsWordlist=./lazyWordLists/altdns_wordlist.txt
  # else
  #   altdnsWordlist=./lazyWordLists/altdns_wordlist_uniq.txt
  # fi
  touch ./$1/$foldername/custom_subdomains_wordlist.txt
  customSubdomainsWordList=./$1/$foldername/custom_subdomains_wordlist.txt
  cp $altdnsWordlist $customSubdomainsWordList

  if [ "$brute" = "1" ]; then
    # ffuf dir uses to store brute output
    mkdir ./$1/$foldername/ffuf/
  fi

  # nmap output
  # mkdir ./$1/$foldername/nmap/
  # brutespray output
  mkdir ./$1/$foldername/brutespray/
  # subfinder list of subdomains
  touch ./$1/$foldername/subfinder-list.txt 
  # assetfinder list of subdomains
  touch ./$1/$foldername/assetfinder-list.txt
  # amass list of subdomains
  touch ./$1/$foldername/amass-list.txt
  # shuffledns list of subdomains
  touch ./$1/$foldername/shuffledns-list.txt
  # gau/waybackurls list of subdomains
  touch ./$1/$foldername/wayback-subdomains-list.txt
  # gau list of only params
  touch ./$1/$foldername/wayback_params_list.txt

  # mkdir ./$1/$foldername/reports/
  # echo "Reports goes to: ./${1}/${foldername}"

    recon $1
    # master_report $1
}

usage(){
  echo "Usage: $FUNCNAME <target> [[-b] | [--brute]] [[-m] | [--mad]]"
  echo "Example: $FUNCNAME example.com --mad"
}

invokation(){
  echo "Warn: unexpected positional argument: $1"
  echo "$(basename $0) [[-h] | [--help]]"
}

# check for help arguments or exit with no arguments
checkhelp(){
  while [ "$1" != "" ]; do
      case $1 in
          -h | --help )           usage
                                  exit
                                  ;;
          # * )                     invokation "$@"
          #                         exit 1
      esac
      shift
  done
}

# check for specifiec arguments (help)
checkargs(){
  while [ "$1" != "" ]; do
      case $1 in
          -b | --brute )          brute="1"
                                  ;;
          -m | --mad )            mad="1"
                                  ;;
          -a | --alt )            alt="1"
                                  ;;
          -w | --wildcard )       wildcard="1"
                                  ;;
          # * )                     invokation $1
          #                         exit 1
      esac
      shift
  done
}


##### Main

if [ $# -eq 0 ]; then
    echo "Error: expected positional arguments"
    usage
    exit 1
else
  if [ $# -eq 1 ]; then
    checkhelp "$@"
  fi
fi

if [ $# -gt 1 ]; then
  checkargs "$@"
fi

# positional parameters test
echo "Check params: $@"
echo "Check # of params: $#"
echo "Check params \$1: $1"
echo "Check params \$brute: $brute"
echo "Check params \$mad: $mad"
echo "Check params \$alt: $alt"
echo "Check params \$wildcard: $wildcard"

./logo.sh
path=$(pwd)
# to avoid cleanup or `sort -u` operation
foldername=recon-$(date +"%y-%m-%d_%H-%M-%S")

# invoke
main $1
