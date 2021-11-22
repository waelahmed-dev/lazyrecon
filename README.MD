```
  _
 | | __ _ ____ _   _ _ __ ___  ___  ___  _ __
 | |/ _  |_  /| | | |  __/ _ \/ __|/ _ \|  _ \
 | | (_|  / / | | | | | |  __/ (__  (_) | | | 
 |_|\__ _|___/ \__  |_|  \___|\___|\___/|_| |_v2
               |___/
```

<p align="center">
<a href="https://twitter.com/storenth"><img src="https://img.shields.io/twitter/follow/storenth.svg?style=flat-square&logo=twitter"></a>
<a href="https://www.blackhat.com/us-21/arsenal/schedule/#lazyrecon-v-24051"><img src="https://img.shields.io/static/v1?label=Black%20Hat%20Arsenal&style=flat-square&message=USA%202021&color=1C7EBE"></a>
<a href="https://discord.gg/fR2QVrWBTq"><img src="https://img.shields.io/discord/823151725686554665.svg?style=flat-square&color=97ca00&logo=discord"></a>
<a href="https://bscscan.com/address/0xb9a36d01577d82909cA01e20dB58293A6baa5dDD"><img src="https://img.shields.io/badge/Token-1A3Y-brightgreen?style=flat-square&color=ca00c7&logo=data:image/svg+xml;base64,PHN2ZyBoZWlnaHQ9JzMwMHB4JyB3aWR0aD0nMzAwcHgnICBmaWxsPSIjRTZEQTAwIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjEiIHg9IjBweCIgeT0iMHB4IiB2aWV3Qm94PSIwIDAgMTAwIDEwMCIgZW5hYmxlLWJhY2tncm91bmQ9Im5ldyAwIDAgMTAwIDEwMCIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSI+PHBhdGggZD0iTTMzLjk1NiwxNS4yMzhWOS44OThoMzIuMDg4djUuMzM5SDMzLjk1NnogTTMzLjk1NiwxNS4yMzhoLTUuMzR2NS4zNWg1LjM0VjE1LjIzOHogTTcxLjM4MywyMC41ODd2LTUuMzVoLTUuMzM5djUuMzUgIEg3MS4zODN6IE0yOC42MTYsNTIuNjY2aDEwLjY4OXYtNS4zNWg1LjM1di01LjM0SDI4LjYxNlY1Mi42NjZ6IE01NS4zNDUsNDEuOTc2djUuMzRoNS4zNXY1LjM1aDEwLjY4OFY0MS45NzZINTUuMzQ1eiAgIE02Ni4wNDQsNjMuMzY1aC01LjM1di01LjM1aC01LjM1di01LjM1SDQ0LjY1NXY1LjM1aC01LjM1djUuMzVoLTUuMzV2NS4zMzloMzIuMDg4VjYzLjM2NXogTTI4LjYxNiw2My4zNjV2LTUuMzVoLTUuMzVWNDEuOTc2ICBoLTUuMzV2MjEuMzg5SDI4LjYxNnogTTI4LjYxNiwzNi42MjZoNDIuNzY3djUuMzVoNS4zNVYyMC41ODdoLTUuMzV2MTAuNjg5SDI4LjYxNlYyMC41ODdoLTUuMzV2MTYuMDM5djUuMzVoNS4zNVYzNi42MjZ6ICAgTTY2LjA0NCw3OS40MDNoNS4zMzl2LTUuMzVoLTUuMzM5Vjc5LjQwM3ogTTI4LjYxNiw3OS40MDNoNS4zNHYtNS4zNWgtNS4zNFY3OS40MDN6IE03Ni43MzIsNTguMDE1aC01LjM1djUuMzVoMTAuNjk5VjQxLjk3NiAgaC01LjM1VjU4LjAxNXogTTgyLjA4Miw2My4zNjV2MTYuMDM5aDUuMzRWNjMuMzY1SDgyLjA4MnogTTc2LjczMiw4NC43NDNoNS4zNXYtNS4zNGgtNS4zNVY4NC43NDN6IE02MC42OTQsODQuNzQzdi01LjM0aC01LjM1ICB2LTUuMzVINDQuNjU1djUuMzVoLTUuMzV2NS4zNEgyMy4yNjd2NS4zNWgyMS4zODl2LTUuMzVoMTAuNjg5djUuMzVoMjEuMzg4di01LjM1SDYwLjY5NHogTTE3LjkxNyw3OS40MDN2NS4zNGg1LjM1di01LjM0SDE3LjkxN3ogICBNMTcuOTE3LDYzLjM2NWgtNS4zNHYxNi4wMzloNS4zNFY2My4zNjV6Ij48L3BhdGg+PC9zdmc+"></a>
</p>

Lazyrecon is a subdomain discovery tool that finds and resolves valid subdomains then performs SSRF/LFI/SQLi fuzzing, brute-force and port scanning. It has a simple modular architecture and is optimized for speed while working with github and wayback machine.

# Features
- Super fast asynchronous execution
- CI/CD ready
- HTML/pdf reports
- Discord integration
- Background listen server
- Domain name, list of domains, IP, CIDR input - notations support
- Teardown and program exit housekeeping
## Workflow
You can use a stateful/stateless build agent (worker). There is no additional time is required for provisioning.
It may seem tricky because some of the tools require a root user.
1. Fill in these required environment variables inside: `./lazyconfig`:
```bash
export HOMEUSER= # your user: e.g.: kali
export HOMEDIR= # user's home dir e.g.: /home/kali
export STORAGEDIR= # where output saved, e.g.: ${HOMEDIR}/lazytargets
export GITHUBTOKEN= # a personal access token (git PAT)
export DISCORDWEBHOOKURL= # https://discord.com/api/webhooks/{webhook.id}/{webhook.token}
export GOPATH=$HOMEDIR/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$HOME/go/bin:$HOMEDIR/go/bin
export GO111MODULE=on
```
2. Enable new environment `source ./lazyconfig`
3. Call `sudo -E ./install.sh`
4. Execute `sudo -E ./lazyrecon.sh "hackerone.com"`


# About

This script is intended to automate your reconnaissance process in an organized fashion by performing the following:

- Creates a dated folder with recon notes for a target
- Grabs subdomains using `subfinder`, `assetfinder`, `gau`, `waybackurls`, `github-subdomains`
- Additionally finds new subdomains through alterations and permutations using `dnsgen`
- Searches subnets and new assets using math `Mode`
- Filters out live subdomains from a list of hosts using `puredns`
- Checks 1-200,8000-10000 for http(s) probes using `httpx`
- Gets visual part using `headless chromium`
- Performs `masscan` on live servers
- Scanns for known paths and CVEs using `nuclei`
- Shots for [SSRF](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)/[LFI](https://www.allysonomalley.com/2021/02/11/burpparamflagger-identifying-possible-ssrf-lfi-insertion-points/)/SQLi based on fetched DOM's and Wayback machine's data
- Checks for 401/403 bypass using [bypass-403](https://github.com/storenth/bypass-403/)
- Performs `ffuf` supercharged by `interlace` using custom WordList based on the [top10000.txt](https://github.com/danielmiessler/RobotsDisallowed/blob/master/top10000.txt)
- Generates report and send it to Discord

The point is to get a list of live IPs (in form of socket addresses), attack available network protocols, check for common CVEs, perform very simple directory bruteforce then use provided reports for manual research.

# Installing & Testing
- `Linux` & `Mac` tested
## Prerequirements
```bash
python >= 3.7
pip3 >= 19.0
go >= 1.17
```
All installation methods [can be found here](INSTALL.md).
You can check if the dependencies are installed correctly on your machine by running the following tests:
```bash
./test/test_nuclei_templates.sh "./test/nuclei_templates_list.txt"
./test/test_install.sh "./test/dependencies_list.txt"
```
If you faced with some issues, feel free to join [Discord](https://discord.gg/fR2QVrWBTq), open PR or file the bug.

# Usage
Execute with `sudo` because of `masscan`:
```bash
▶ sudo -E ./lazyrecon.sh tesla.com --wildcard
```

| **Parameter**  | **Description**                                       | **Example**                                     |
| ---------------|-------------------------------------------------------|-------------------------------------------------|
| --wildcard     | Subdomains reconnaissance '*.tesla.com' (default)     | ./lazyrecon.sh tesla.com --wildcard             |
| --single       | One target instance 'tesla.com'                       | ./lazyrecon.sh tesla.com --single               |
| --ip           | Single IP of the target machine                       | ./lazyrecon.sh 192.168.0.1 --single --ip        |
| --list         | List of subdomains to process for                     | ./lazyrecon.sh "./testa.txt" --list             |
| --cidr         | Perform network recon, CIDR notation                  | ./lazyrecon.sh "192.168.0.0/16" --cidr          |
| --mad          | Wayback machine's stuff                               | ./lazyrecon.sh tesla.com --mad                  |
| --fuzz         | SSRF/LFI/SQLi fuzzing                                 | ./lazyrecon.sh tesla.com --mad --fuzz           |
| --alt          | Additionally permutate subdomains (*.tesla.com only)  | ./lazyrecon.sh tesla.com --wildcard --alt       |
| --brute        | Basic directory bruteforce (time sensitive)           | ./lazyrecon.sh tesla.com --single --brute       |
| --discord      | Send notifications to discord                         | ./lazyrecon.sh tesla.com --discord              |
| --quiet        | Enable quiet mode                                     | ./lazyrecon.sh tesla.com --quiet                |


# Methodology
0. Use [dnsperftest](https://github.com/cleanbrowsing/dnsperftest) to know your best resolvers
1. Run `./lazyrecon.sh`
2. Check output reports of chromium, nuclei, masscan, `403-bypass-output.txt` `_listen_server.log`, `lfi-matched-url.txt`
3. Pick the right target for you based on screenshot and ports opened.
4. Use Firefox and Burp to proxy all requests while exploratory testing
5. Try to find file upload vulnerabilities
6. Perform Google, Trello, Atlassian, Github, Bitbucket dorking
7. Check JS sources for credentials, API endpoints
8. Investigate `XHR` requests, fuzz parameters and variables
9. Check exploit-db.com for target-specific CVE based on `nmap`/`masscan` output
10. GET/POST Bruteforce for directories: fuzbo0oM-top10000 --> raft --> target specific
11. Continue bruteforcing using custom Headers (X-Custom-IP-Authorization: 127.0.0.1; X-Original-URL:)
12. Try bypass 401/403 errors using [notable](https://github.com/filedescriptor/Unicode-Mapping-on-Domain-names) methods (`%23`, `/%2e/`, `admin.php%2500.md` etc)
13. Use XSS automation [xsscrapy.py](https://github.com/DanMcInerney/xsscrapy) or [XSSTRON](https://github.com/RenwaX23/XSSTRON)
14. Try another XSS:
```
Referer: javascript:alert('XSS');
https://www.twitterflightschool.com/student/award/████████?referer=javascript:alert(document.domain)
```


# Origin
This project was inspired by original v1.0 [Ben Sadeghipour](https://github.com/nahamsec/lazyrecon) and aimed to implement some of the best practices like [Mechanizing the Methodology](https://www.youtube.com/watch?v=L_qoz2_Qyhk), [TBHM](https://docs.google.com/presentation/d/1MWWXXRvvesWL8V-GiwGssvg4iDM58_RMeI_SZ65VXwQ), [Subdomain Takeovers](https://www.hackerone.com/blog/Guide-Subdomain-Takeovers), [Request Smuggling](https://portswigger.net/web-security/request-smuggling), [SSRF](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF), [LFI](https://www.allysonomalley.com/2021/02/11/burpparamflagger-identifying-possible-ssrf-lfi-insertion-points/) and [Bruteforce](https://danielmiessler.com/blog/the-most-interesting-disallowed-directories/) based on [Custom wordlist](https://www.youtube.com/watch?v=W4_QCSIujQ4&t=1237s&ab_channel=Nahamsec).
## Notable articles
1. [IDOR](https://www.aon.com/cyber-solutions/aon_cyber_labs/finding-more-idors-tips-and-tricks/?utm_source=newsletter&utm_medium=email&utm_campaign=bug_bytes_110_scope_based_recon_finding_more_idors_how_to_hack_sharepoint&utm_term=2021-02-17)
2. [SSRF automation](https://notifybugme.medium.com/finding-ssrf-by-full-automation-7d2680091d68) and [SSRF RCE](https://rez0.blog/hacking/2019/11/29/rce-via-imagetragick.html)
3. [Enumeration guide](https://sidxparab.gitbook.io/subdomain-enumeration-guide/active-enumeration/dns-bruteforcing)
## BlackHat USA
Lazyrecon was invited and presented at the [BlackHat USA 2021](https://www.blackhat.com/us-21/arsenal/schedule/#lazyrecon-v-24051). Now it is officially on the [BlackHat Arsenal track](https://github.com/toolswatch/blackhat-arsenal-tools/blob/master/exploitation/lazyrecon.md).

## Notes
**Acknowledgement:** This code was created for personal use with hosts you able to hack/explore by any of the known bug bounty program. Use it at your own risk.

[See release notes](misc/NOTES.MD)

# Crypto token
- [1A3Y](https://bscscan.com/token/0xb9a36d01577d82909ca01e20db58293a6baa5ddd) helps Lazyrecon create new features.
- Track the token activity on [poocoin](https://poocoin.app/tokens/0xb9a36d01577d82909ca01e20db58293a6baa5ddd)
- 💬 Join 1A3Y's [telegram](https://t.me/lazyrecontoken)

