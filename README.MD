```
  _
 | | __ _ ____ _   _ _ __ ___  ___  ___  _ __
 | |/ _  |_  /| | | |  __/ _ \/ __|/ _ \|  _ \
 | | (_|  / / | | | | | |  __/ (__  (_) | | | 
 |_|\__ _|___/ \__  |_|  \___|\___|\___/|_| |_v2
               |___/
```

<p align="center">
<a href="https://twitter.com/storenth"><img src="https://img.shields.io/twitter/follow/storenth.svg?logo=twitter"></a>
<a href="https://discord.gg/fR2QVrWBTq"><img src="https://img.shields.io/discord/823151725686554665.svg?logo=discord"></a>
</p>

Lazyrecon is a subdomain discovery tool that discovers and resolves valid subdomains then performs SSRF/LFI/SQLi fuzzing and port scanning. It has a simple modular architecture and is optimized for speed while working with github and wayback machine.

# CI/CD flow
<h3 align="center">
  <img src="readme_img/ci-cd-flow.png" alt="lazyrecon-flow" width="700px"></a>
</h3>

# About

This script is intended to automate your reconnaissance process in an organized fashion by performing the following:

- Create a dated folder with recon notes for target
- Grab subdomains using `subfinder`, `assetfinder`, `gau`, `waybackurls`, `github-subdomains`
- Subdomain discovery through alterations and permutations using `altdns` and `dnsgen`
- Filtering out live subdomains from a list of hosts using `shuffledns`
- Check 1-200,8000-10000 for http(s) probes using `httpx`
- Get visual part using `aquatone`
- Perform `masscan` on live servers
- Automatically brute-forces services with default credentials using `hydra`
- Scanning for known paths and CVEs using `nuclei`
- Shot for [SSRF](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)/[LFI](https://www.allysonomalley.com/2021/02/11/burpparamflagger-identifying-possible-ssrf-lfi-insertion-points/)/SQLi based on wayback machine's data like [ParamSpider](https://github.com/devanshbatham/ParamSpider) but no reduces the sizes of archive
- Check for potential request smuggling vulnerabilities using `smuggler`
- Perform `ffuf` using custom WordList based on the [top10000.txt](https://github.com/danielmiessler/RobotsDisallowed/blob/master/top10000.txt)
- Send pass/fail reports to Discord
- [WIP][x] Generate HTML report in case of a potentially vulnerable domain found.

The point is to get a list of live IPs, attack available network protocols, check for common CVEs, perform very simple directory bruteforce then use provided reports for manual research.

# Features
1. Super fast asynchronous execution
2. CI/CD ready
3. Teardown and program exit housekeeping
4. Domain name, list of domains, IP, CIDR target notation
5. Discord integration
# Installing
Tested on `MacOS` and `Linux`
- Config your environment variables: `HOMEUSER` and `ATTACKERURL`, see full list at ./lazyconfig
- Launch your listen server for connect-back TCP connections
- Use option `nuclei -ut -ud '$PWD/'` to use it properly, but for LFI update templates with [storenth-lfi](https://github.com/storenth/nuclei-templates/blob/master/vulnerabilities/other/storenth-lfi.yaml) till the time [projectdiscovery](https://github.com/projectdiscovery) introduce feature for dynamic replacement of parameters.
- Update your local `~/.gf` with `./gfpatterns/`
- Make sure all tools correctly installed and enabled with execute permissions: `chmod +x`
1. [subfinder](https://github.com/projectdiscovery/subfinder)
2. [assetfinder](https://github.com/tomnomnom/assetfinder)
3. [github-subdomains](https://github.com/gwen001/github-subdomains)
4. [github-endpoints](https://github.com/gwen001/github-endpoints)
5. [aquatone](https://github.com/michenriksen/aquatone)
6. [waybackurls](https://github.com/tomnomnom/waybackurls)
7. [gau](https://github.com/lc/gau)
8. [altdns](https://github.com/infosec-au/altdns)
9. [dnsgen](https://github.com/ProjectAnte/dnsgen/)
10. [shuffledns](https://github.com/projectdiscovery/shuffledns)
11. [masscan](https://github.com/robertdavidgraham/masscan)
12. [dnsx](https://github.com/projectdiscovery/dnsx)
13. [SecLists](https://github.com/danielmiessler/SecLists)
14. [httpx](https://github.com/projectdiscovery/httpx)
15. [nuclei](https://github.com/projectdiscovery/nuclei)
16. [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
17. [smuggler](https://github.com/storenth/requestsmuggler)
18. [ffuf](https://github.com/ffuf/ffuf)
19. [hydra](https://github.com/vanhauser-thc/thc-hydra)
20. [gf](https://github.com/tomnomnom/gf)
21. [unfurl](https://github.com/tomnomnom/unfurl)
22. [sqlmap](https://github.com/sqlmapproject/sqlmap)
23. [gospider](https://github.com/jaeles-project/gospider)
24. [hakrawler](https://github.com/hakluke/hakrawler)
25. [ssrf-headers-tool](https://github.com/storenth/Bug-Bounty-Toolz/blob/master/ssrf.py)
26. [storenth-lfi](https://github.com/storenth/nuclei-templates/blob/master/vulnerabilities/other/storenth-lfi.yaml)
> (You may copy each executable dependency to `/usr/local/bin/`, create symlinc like: `ln -s $HOME/smuggler/smuggler.py /usr/local/bin/smuggler`, or just export it to the PATH `export PATH=~/masscan/masscan:$PATH`)

If you faced with some issues, feel free to join [Discord](https://discord.gg/fR2QVrWBTq), open PR or file the bug.

# Usage
Execute with `sudo` because of `masscan`:
```bash
sudo ./lazyrecon.sh tesla.com --wildcard
```

| **Parameter**  | **Description**                                       | **Example**                                     |
| ---------------|-------------------------------------------------------|-------------------------------------------------|
| --wildcard     | Subdomains reconnaissance '*.tesla.com' (default)     | sudo ./lazyrecon.sh tesla.com --wildcard        |
| --single       | One target instance 'tesla.com'                       | sudo ./lazyrecon.sh tesla.com --single          |
| --ip           | Single IP of the target machine                       | sudo ./lazyrecon.sh 192.168.0.1 --single --ip   |
| --list         | List of subdomains to process for (time sensitive)    | sudo ./lazyrecon.sh "./testa.txt" --list        |
| --cidr         | Perform network recon, CIDR notation                  | sudo ./lazyrecon.sh "192.168.0.0/16" --cidr     |
| --mad          | Wayback machine's stuff                               | sudo ./lazyrecon.sh tesla.com --mad             |
| --fuzz         | SSRF/LFI fuzzing                                      | sudo ./lazyrecon.sh tesla.com --mad --fuzz      |
| --alt          | Additionally permutate subdomains (*.tesla.com only)  | sudo ./lazyrecon.sh tesla.com --wildcard --alt  |
| --brute        | Basic directory bruteforce (time sensitive)           | sudo ./lazyrecon.sh tesla.com --single --brute  |
| --discord      | Send notifications to discord                         | sudo ./lazyrecon.sh tesla.com --single --discord|


# Notes

 - Use [dnsperftest](https://github.com/cleanbrowsing/dnsperftest) to know your best resolvers
 - `Sublist3r` replaced with `subfinder` based on Twitter [discussion](https://twitter.com/Jhaddix/status/1293118260808843264)
 - `nmap` replaced with `masscan` based on its features and Twitter [duscussion](https://twitter.com/DanielMiessler/status/1286721113343447040)
 - `smuggler` forked from its [original](https://github.com/gwen001/pentest-tools/blob/master/smuggler.py) aimed to get lightweight solution included this [PR](https://github.com/gwen001/pentest-tools/pull/10)
 - ~~`grep` `meg`'s output for [Location](https://twitter.com/hunter0x7/status/1293168500672954368) in order to exclude 301/302 status codes~~
 (replaced with `httpx -fc 301,302` approach)
 - ~~`httpx -ip` used without `dnsprobe` based on @pdiscoveryio Twitter [answer](https://twitter.com/pdiscoveryio/status/1338163970557894656)~~
 - `altdns` used based on [Scrutiny on the bug bounty](https://docs.google.com/presentation/d/1PCnjzCeklOeGMoWiE2IUzlRGOBxNp8K5hLQuvBNzrFY/)
 - `massdns` fully replaced with `shuffledns` because of [issue](https://github.com/blechschmidt/massdns/issues/73)
 - WIP: you can track activity in Projects To Do board


**Acknowledgement:** This code was created for personal use with hosts you able to hack/explore by any of the known bug bounty program. Use it at your own risk.

# Methodology
1. Run `./lazyrecon.sh`
2. Explore file upload vulnerabilities
3. Google dorking
4. Trello, Atlassian, Github, Bitbucket dorking
5. Check JS sources for credentials, API endpoints, debug for variables
6. Check `XHR` API requests, fuzz parameters
7. Check exploit-db.com for known target-specific CVE
8. Bruteforce for directories: fuzbo0oM-top10000 --> raft --> target specific
9. Continue brute with custom Headers (X-Custom-IP-Authorization: 127.0.0.1; X-Original-URL:)
10. Start new brute with POST method
11. Try bypass 401/403 errors using [notable](https://github.com/filedescriptor/Unicode-Mapping-on-Domain-names) methods (`%23`, `/%2e/`, `admin.php%2500.md` etc)
12. `hydra`, 21, 22, 25, etc ports
13. XSS [xsscrapy.py](https://github.com/DanMcInerney/xsscrapy) or [XSSTRON](https://github.com/RenwaX23/XSSTRON)

# Origin
This project was inspired by original v1.0 [Ben Sadeghipour](https://github.com/nahamsec/lazyrecon) and aimed to implement some of the best practices like [Mechanizing the Methodology](https://www.youtube.com/watch?v=L_qoz2_Qyhk), [TBHM](https://docs.google.com/presentation/d/1MWWXXRvvesWL8V-GiwGssvg4iDM58_RMeI_SZ65VXwQ), [Subdomain Takeovers](https://www.hackerone.com/blog/Guide-Subdomain-Takeovers), [Request Smuggling](https://portswigger.net/web-security/request-smuggling), [SSRF](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF), [LFI](https://www.allysonomalley.com/2021/02/11/burpparamflagger-identifying-possible-ssrf-lfi-insertion-points/) and [Bruteforce](https://danielmiessler.com/blog/the-most-interesting-disallowed-directories/) based on [Custom wordlist](https://www.youtube.com/watch?v=W4_QCSIujQ4&t=1237s&ab_channel=Nahamsec).
# Notable articles
1. IDOR: https://www.aon.com/cyber-solutions/aon_cyber_labs/finding-more-idors-tips-and-tricks/?utm_source=newsletter&utm_medium=email&utm_campaign=bug_bytes_110_scope_based_recon_finding_more_idors_how_to_hack_sharepoint&utm_term=2021-02-17
2. SSRF: https://notifybugme.medium.com/finding-ssrf-by-full-automation-7d2680091d68 and https://rez0.blog/hacking/2019/11/29/rce-via-imagetragick.html