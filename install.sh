#!/bin/bash -e

# Script works in current directory

MACOS=
if [[ "$OSTYPE" == "darwin"* ]]; then
  MACOS="1"
fi

# CI/CD dependencies
# to use github API you need 
third_party_go_dependencies(){
    # Third-party tools
    declare -A gotools
    gotools["subfinder"]="GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    gotools["shuffledns"]="GO111MODULE=on go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns"
    gotools["simplehttpserver"]="GO111MODULE=on go get -v github.com/projectdiscovery/simplehttpserver"
    gotools["nuclei"]="GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    nuclei -ut -ud '$PWD/'

    gotools["mapcidr"]="GO111MODULE=on go get -v github.com/projectdiscovery/mapcidr/cmd/mapcidr"
    gotools["httpx"]="GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx"
    gotools["dnsx"]="GO111MODULE=on go get -v github.com/projectdiscovery/dnsx/cmd/dnsx"

    gotools["assetfinder"]="go get -v github.com/tomnomnom/assetfinder"
    gotools["waybackurls"]="go get github.com/tomnomnom/waybackurls"
    gotools["qsreplace"]="go get -v github.com/tomnomnom/qsreplace"
    gotools["unfurl"]="go get -v github.com/tomnomnom/unfurl"
    gotools["gf"]="go get -v github.com/tomnomnom/gf"
    gotools["gospider"]="go get -u github.com/jaeles-project/gospider"
    gotools["gau"]="GO111MODULE=on go get -u -v github.com/lc/gau"
    gotools["ffuf"]="go get -u github.com/ffuf/ffuf"
}

custom_origin_dependencies() {
    git clone https://github.com/blechschmidt/massdns.git
    cd massdns; make; ln -s $PWD/bin/massdns /usr/local/bin/massdns; cd -

    git clone https://github.com/robertdavidgraham/masscan.git
    cd masscan; make; ln -s $PWD/bin/masscan /usr/local/bin/masscan; cd -

    git clone https://github.com/storenth/github-search.git
    ln -s $PWD/github-search/github-endpoints.py /usr/local/bin/github-endpoints
    ln -s $PWD/github-search/github-subdomains.py /usr/local/bin/github-subdomains

    git clone https://github.com/storenth/Bug-Bounty-Toolz.git
    ln -s $PWD/Bug-Bounty-Toolz/ssrf.py /usr/local/bin/ssrf-headers-tool

    wget https://raw.githubusercontent.com/storenth/nuclei-templates/master/vulnerabilities/other/storenth-lfi.yaml
    mv $PWD/storenth-lfi.yaml $PWD/nuclei-templates/vulnerabilities/other/

    if [[ -n "$MACOS" ]]; then
        wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_macos_amd64_1.7.0.zip
        unzip $PWD/aquatone_macos_amd64_1.7.0.zip -d aquatone_relese
    else
        wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
        unzip $PWD/aquatone_linux_amd64_1.7.0.zip -d aquatone_relese
    fi
    ln -s aquatone_relese/aquatone /usr/local/bin/aquatone
}

notification(){
    echo
    echo "Dependencies insalled in $PWD"
}

main() {
    # Entry point
    custom_origin_dependencies # massdns needs before shuffledns
    third_party_go_dependencies

    notification
}

main
exit 0
