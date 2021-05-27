#!/bin/bash -x

# Script works in current directory

# . ./lazyconfig

MACOS=
if [[ "$OSTYPE" == "darwin"* ]]; then
  MACOS="1"
fi


# CI/CD dependencies
third_party_go_dependencies(){
    # Third-party tools
    gotools[0]="go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    gotools[1]="go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns"
    gotools[2]="go get -v github.com/projectdiscovery/interactsh/cmd/interactsh-client"
    gotools[3]="go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    gotools[4]="go get -v github.com/projectdiscovery/mapcidr/cmd/mapcidr"
    gotools[5]="go get -v github.com/projectdiscovery/httpx/cmd/httpx"
    gotools[6]="go get -v github.com/projectdiscovery/dnsx/cmd/dnsx"
    gotools[7]="go get -v github.com/tomnomnom/assetfinder"
    gotools[8]="go get -v github.com/tomnomnom/waybackurls"
    gotools[9]="go get -v github.com/tomnomnom/qsreplace"
    gotools[10]="go get -v github.com/tomnomnom/unfurl"
    gotools[11]="go get -u github.com/tomnomnom/gf"
    gotools[12]="go get -u github.com/jaeles-project/gospider"
    gotools[13]="go get -u -v github.com/lc/gau"
    gotools[14]="go get -u github.com/ffuf/ffuf"

    for gotool in "${gotools[@]}"; do
        $gotool
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
    mv -f $PWD/storenth-lfi.yaml $HOMEDIR/nuclei-templates/vulnerabilities/other

    find . -name "requirements.txt" -type f -exec pip3 install -r '{}' ';'
}

# need to be in $PATH in case no chrome installed: ./chromium-latest-linux/latest/chrome
chromium_dependencies(){
    if ! type chromium; then
        git clone https://github.com/storenth/chromium-latest-linux.git
        if cd chromium-latest-linux; then
            if [[ -n "$MACOS" ]]; then
                # mac development https://github.com/storenth/chromium-latest-linux
                ./install-update-mac.sh
                ln -s $PWD/latest/Chromium.app/Contents/MacOS/Chromium /usr/local/bin/chromium
            else
                ./update.sh
                ln -s $PWD/latest/chrome /usr/local/bin/chromium
            fi
            cd -
        fi
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
