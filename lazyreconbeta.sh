#!/bin/bash

checkhost(){
  echo "[phase 2] Starting host/DNS live testing..."
  while read subdomain; do
    if host -t A "$subdomain" > /dev/null;
    then
      # If host is live, print it into
      # a file called "live.txt".
      echo "$subdomain" >> ./$1/$foldername/host_live.txt
    else
      # need to implement dig here
      echo "$subdomain" >> ./$1/$foldername/unreachable.txt
    fi
  done < ./$1/$foldername/subdomain-list.txt
}

checkhttprobe(){
  echo "[phase 3] Starting httprobe testing..."
  cat ./$1/$foldername/host_live.txt | httprobe > ./$1/$foldername/live.txt
}

checkmeg(){
  echo "[phase 4] Starting meg sieving on live servers..."
  ../meg/meg -d 10 -c 200 / ./$1/$foldername/live.txt ./$1/$foldername/megoutput
}

sortliveservers(){
  echo "[phase 5] Sorting hosts..."
  cat ./$1/$foldername/live.txt | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | sort -u > ./$1/$foldername/sortedlive.txt
}

checktakeover(){
  sleep 5
  echo "[phase 6] Starting grep for search vulnerable hosts..."
  cat ./$1/$foldername/sortedlive.txt | while read line;
    do
      for X in ./$1/$foldername/megoutput/${line}/*
        do
          if grep -l 'Repository not found\|The specified bucket does not exist\|Github Pages site here\|No such app\|Sorry, this shop is currently unavailable\|404 Blog is not found\|is not a registered InCloud YouTrack' "$X"; then
            cat "$X"
            echo "$line" >> ./$1/$foldername/vulnerable.txt
            # need to collect meg output also here to create appropriate report in the next steps
          fi
        done
    done

  if [ -s ./$1/$foldername/vulnerable.txt ]; then
    # echo "${yellow}[phase 3] Start directory bruteforce...${reset}"
    printf "${RB_RED}%sTakeover found!${RESET}"
    printf "\n"
    # cat ./$1/$foldername/live.txt | sort | while read line; do
    #   report $1
    # done
  else
      echo "There are no Subdomain takeover vulnerable host found."
  fi
}

smuggler(){
  echo "[phase 7] Try to find request smuggling vulnerabilities..."
  ../requestsmuggler/smuggler.py -u ./$1/$foldername/live.txt

  # check for VULNURABLE keyword
  if [ -s ./$1/$foldername/smuggler/output ]; then
    cat ./$1/$foldername/smuggler/output | grep 'VULNERABLE' > ./$1/$foldername/smuggler/smugglinghosts.txt
    if [ -s ./$1/$foldername/smuggler/smugglinghosts.txt ]; then
      printf "${RB_RED}%sSmuggling vulnerability found!${RESET}"
      printf "\n"
    else
      echo "There are no vulnerable host found"
    fi
  else
    echo "smuggler doesn't provide the output, check it issue!"
  fi
}

recon(){
  echo "[phase 1] Enumerating all known domains using sublist3r..."
  python3 ../Sublist3r/sublist3r.py -d $1 -t 10 -v -o ./$1/$foldername/subdomain-list.txt

  checkhost $1
  checkhttprobe $1
  checkmeg $1
  sortliveservers $1
  checktakeover $1
  smuggler $1

  echo "Generating HTML-report here..."
  echo "Lazy done."
}

# Use colors, but only if connected to a terminal, and that terminal
# supports them.
if [ -t 1 ]; then
  RB_RED=$(printf '\033[38;5;196m')
  RB_ORANGE=$(printf '\033[38;5;202m')
  RB_YELLOW=$(printf '\033[38;5;226m')
  RB_GREEN=$(printf '\033[38;5;082m')
  RB_BLUE=$(printf '\033[38;5;021m')
  RB_INDIGO=$(printf '\033[38;5;093m')
  RB_VIOLET=$(printf '\033[38;5;163m')

  RED=$(printf '\033[31m')
  GREEN=$(printf '\033[32m')
  YELLOW=$(printf '\033[33m')
  BLUE=$(printf '\033[34m')
  BOLD=$(printf '\033[1m')
  RESET=$(printf '\033[m')
else
  RB_RED=""
  RB_ORANGE=""
  RB_YELLOW=""
  RB_GREEN=""
  RB_BLUE=""
  RB_INDIGO=""
  RB_VIOLET=""

  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  BOLD=""
  RESET=""
fi

logo(){
  printf "${BLUE}%s\n" "reconnaissance starting up!"
  printf '  %s _%s        %s    %s      %s     %s   %s     %s     %s \n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_RESET
  printf '  %s| |%s __ _ %s____%s _   _ %s_ __ %s___%s  ___ %s ___%s  _ __%s\n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_RESET
  printf '  %s| |%s/ _  |%s_  /%s| | | %s|  __%s/ _ \%s/ __|%s/ _ \%s|  _ \ %s\n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_RESET
  printf '  %s| |%s (_|  %s/ / %s| | | %s| | %s|  __/%s (__ %s (_) %s| | | %s\n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_RESET
  printf '  %s|_|%s\__ _|%s___/%s \__  %s|_ %s  \___|%s\___|%s\___/%s|_| |_ %s\n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_RESET
  printf '  %s   %s      %s    %s |___/%s    %s       %s     %s     %s       %s\n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_RESET
  printf "\n"
  printf "${BLUE}%s\n" "nahamsec/lazyrecon v1.0 forked by storenth/lazyrecon v2.0"
  printf "${BLUE}${BOLD}%s${RESET}\n" "To keep up on the latest news and updates, follow me on Twitter: https://twitter.com/storenth"
  printf "${BLUE}${BOLD}%s${RESET}\n" "I am looking for your support: https://github.com/storenth/lazyrecon"
  printf "\n"
}

main(){
  logo

  if [ -d "./$1" ]
  then
    echo "This is a known target."
  else
    mkdir ./$1
  fi

  mkdir ./$1/$foldername
  mkdir ./$1/$foldername/reports/
  mkdir ./$1/$foldername/megoutput/
  touch ./$1/$foldername/unreachable.txt
  touch ./$1/$foldername/subdomain-list.txt
  touch ./$1/$foldername/host_live.txt
  touch ./$1/$foldername/live.txt
  touch ./$1/$foldername/sortedlive.txt
  touch ./$1/$foldername/vulnerable.txt

  echo "Reports goes to: ./${1}/${foldername}"

    recon $1
    # master_report $1
}

if [[ -z $@ ]]; then
  echo "Error: no targets specified."
  echo "Usage: ./lazyrecon.sh <target>"
  exit 1
fi

path=$(pwd)
# to avoid cleanup or `sort -u` operation
foldername=recon-$(date +"%y-%m-%d_%H-%M-%S")
main $1
