#!/bin/bash -e

# Script works in current directory

MACOS=
if [[ "$OSTYPE" == "darwin"* ]]; then
  MACOS="1"
fi

export GOPATH=$HOME/go
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH
export GO111MODULE=on

# CI/CD dependencies
third_party_go_dependencies(){
    # Third-party tools
    declare -A gotools
    gotools["subfinder"]="go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    gotools["shuffledns"]="go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns"
    gotools["simplehttpserver"]="go get -v github.com/projectdiscovery/simplehttpserver"
    gotools["nuclei"]="go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    gotools["mapcidr"]="go get -v github.com/projectdiscovery/mapcidr/cmd/mapcidr"
    gotools["httpx"]="go get -v github.com/projectdiscovery/httpx/cmd/httpx"
    gotools["dnsx"]="go get -v github.com/projectdiscovery/dnsx/cmd/dnsx"
    gotools["assetfinder"]="go get -v github.com/tomnomnom/assetfinder"
    gotools["waybackurls"]="go get github.com/tomnomnom/waybackurls"
    gotools["qsreplace"]="go get -v github.com/tomnomnom/qsreplace"
    gotools["unfurl"]="go get -v github.com/tomnomnom/unfurl"
    gotools["gf"]="go get -v github.com/tomnomnom/gf"
    gotools["gospider"]="go get -u github.com/jaeles-project/gospider"
    gotools["gau"]="go get -u -v github.com/lc/gau"
    gotools["ffuf"]="go get -u github.com/ffuf/ffuf"

    for gotool in "${!gotools[@]}"; do
        eval type $gotool || { eval ${gotools[$gotool]}; }
    done
    nuclei -ut -ud "${PWD}/nuclei-templates"
}

custom_origin_dependencies() {
    type hydra || { git clone https://github.com/vanhauser-thc/thc-hydra.git && cd thc-hydra && ./configure && make && make install && cd - }

    type massdns || { git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && ln -s $PWD/bin/massdns /usr/local/bin/massdns && cd - }

    type masscan || { git clone https://github.com/robertdavidgraham/masscan.git && cd masscan; make && ln -s $PWD/bin/masscan /usr/local/bin/masscan && cd - }

    type github-endpoints || { git clone https://github.com/storenth/github-search.git && \
                               ln -s $PWD/github-search/github-endpoints.py /usr/local/bin/github-endpoints && \
                               ln -s $PWD/github-search/github-subdomains.py /usr/local/bin/github-subdomains }

    type ssrf-headers-tool || { git clone https://github.com/storenth/Bug-Bounty-Toolz.git && \
                                ln -s $PWD/Bug-Bounty-Toolz/ssrf.py /usr/local/bin/ssrf-headers-tool }

    wget https://raw.githubusercontent.com/storenth/nuclei-templates/master/vulnerabilities/other/storenth-lfi.yaml
    mv $PWD/storenth-lfi.yaml $PWD/nuclei-templates/vulnerabilities/other/

    if ! type aquatone; then
        if [[ -n "$MACOS" ]]; then
            wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_macos_amd64_1.7.0.zip
            unzip $PWD/aquatone_macos_amd64_1.7.0.zip -d aquatone_relese
        else
            wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
            unzip $PWD/aquatone_linux_amd64_1.7.0.zip -d aquatone_relese
        fi
        ln -s aquatone_relese/aquatone /usr/local/bin/aquatone
    fi

    find . -name "requirements.txt" -type f -exec pip3 install -r '{}' ';' 
}

notification(){
    echo
    echo "Dependencies insalled in $PWD"
}

main() {
    # Entry point
    third_party_go_dependencies
    custom_origin_dependencies

    notification
}

main
exit 0
