#!/bin/bash -x

# Script works in current directory
# for MAC users nmap needs to be pre-installed

MACOS=
if [[ "$OSTYPE" == "darwin"* ]]; then
  MACOS="1"
else
    if ! type nmap; then
        apt update -y
        apt install -y nmap
    fi
fi

export GOPATH=$HOMEDIR/go
# export GOROOT=/usr/local/go
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
    gotools["waybackurls"]="go get -v github.com/tomnomnom/waybackurls"
    gotools["qsreplace"]="go get -v github.com/tomnomnom/qsreplace"
    gotools["unfurl"]="go get -v github.com/tomnomnom/unfurl"
    gotools["gf"]="go get -u github.com/tomnomnom/gf"
    gotools["gospider"]="go get -u github.com/jaeles-project/gospider"
    gotools["gau"]="go get -u -v github.com/lc/gau"
    gotools["ffuf"]="go get -u github.com/ffuf/ffuf"

    for gotool in "${!gotools[@]}"; do
        type $gotool || ${gotools[$gotool]}
    done

    nuclei -update-templates

    mkdir -p $HOMEDIR/.gf
    cp -r ./gfpatterns/* $HOMEDIR/.gf
}

custom_origin_dependencies() {
    if ! type hydra; then
        git clone https://github.com/vanhauser-thc/thc-hydra.git
        if cd thc-hydra; then
            ./configure
            make && make install
            cd -
        fi
    fi

    if ! type massdns; then
        git clone https://github.com/blechschmidt/massdns.git
        if cd massdns; then
            make
            ln -s $PWD/bin/massdns /usr/local/bin/massdns
            cd -
        fi
    fi

    if ! type masscan; then
        git clone https://github.com/robertdavidgraham/masscan.git
        if cd masscan; then
            make
            ln -s $PWD/bin/masscan /usr/local/bin/masscan
            cd -
        fi
    fi

    if ! type github-endpoints; then
        git clone https://github.com/storenth/github-search.git
        ln -s $PWD/github-search/github-endpoints.py /usr/local/bin/github-endpoints
        ln -s $PWD/github-search/github-subdomains.py /usr/local/bin/github-subdomains
    fi

    if ! type ssrf-headers-tool; then
        git clone https://github.com/storenth/Bug-Bounty-Toolz.git
        ln -s $PWD/Bug-Bounty-Toolz/ssrf.py /usr/local/bin/ssrf-headers-tool
    fi

    wget -nc https://raw.githubusercontent.com/storenth/nuclei-templates/master/vulnerabilities/other/storenth-lfi.yaml
    mv -uf $PWD/storenth-lfi.yaml $HOMEDIR/nuclei-templates/vulnerabilities/other

    if ! type aquatone; then
        if [[ -n "$MACOS" ]]; then
            wget -nc https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_macos_amd64_1.7.0.zip
            unzip -n $PWD/aquatone_macos_amd64_1.7.0.zip -d aquatone_relese
        else
            wget -nc https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
            unzip -n $PWD/aquatone_linux_amd64_1.7.0.zip -d aquatone_relese
        fi
        ln -s $PWD/aquatone_relese/aquatone /usr/local/bin/aquatone
    fi

    find . -name "requirements.txt" -type f -exec pip3 install -r '{}' ';'
}

# need to be in $PATH in case no chrome installed: ./chromium-latest-linux/latest/chrome
chromium_dependencies(){
    git clone https://github.com/scheib/chromium-latest-linux.git
    
    if cd chromium-latest-linux; then
        if [[ -n "$MACOS" ]]; then
            echo "Under development on https://github.com/storenth/chromium-latest-linux"
            exit 1
        else
            ./update.sh
        fi
        ln -s $PWD/latest/chrome /usr/local/bin/chromium
        cd -
    fi
}

notification(){
    echo
    echo "Dependencies insalled in $PWD"
}

main() {
    # Entry point
    third_party_go_dependencies
    custom_origin_dependencies
    chromium_dependencies

    notification
}

main
exit 0
