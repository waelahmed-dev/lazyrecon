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

Lazyrecon is a subdomain discovery tool that discovers and resolves valid subdomains and perform SSRF/LFI/SQLi fuzzing. It has a simple modular architecture and is optimized for speed while work with wayback machine.
# Usage
Execute with `sudo` because of `masscan`:
```bash
sudo ./lazyrecon.sh tesla.com
```

| **Parameter** | **Description** | **Example** |
| ---------------|-----------------|-------------|
| --ip       | Call with IP | sudo ./lazyrecon.sh 192.168.0.1 --ip --single |
| --single   | Do not perform subdomain discovery | sudo ./lazyrecon.sh tesla.com --single |
| --wildcard | Perform wildcard filtering for subdomains | sudo ./lazyrecon.sh tesla.com --wildcard |
| --mad      | Executes with wayback machines stuff for target | sudo ./lazyrecon.sh tesla.com --mad --wildcard |
| --fuzz     | Basic SSRF/LFI fuzzing | sudo ./lazyrecon.sh tesla.com --fuzz |
| --alt      | Additionally permutate subdomains | sudo ./lazyrecon.sh tesla.com --alt |
| --brute    | Basic directory bruteforce | sudo ./lazyrecon.sh tesla.com --brute |
| | |
# About

This script is intended to automate your reconnaissance process in an organized fashion by performing the following:

- Create a dated folder with recon notes for target
- Grab subdomains using `subfinder`, `assetfinder`, `gau`, `waybackurls`, `github-subdomains`
- Subdomain discovery through alterations and permutations using `altdns` and `dnsgen`
- Filtering out live subdomains from a list of hosts using `shuffledns`
- Check 0-200,8000-10000 for http probes using `httpx`
- Get visual part using `aquatone`
- Perform `masscan` on live servers
- Automatically brute-forces services with default credentials using `hydra`
- Scanning for known paths and CVEs using `nuclei`
- Executes [SSRF](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)/[LFI](https://www.allysonomalley.com/2021/02/11/burpparamflagger-identifying-possible-ssrf-lfi-insertion-points/)/SQLi based on wayback machine's data like [ParamSpider](https://github.com/devanshbatham/ParamSpider) but no reduce the sizes of archive
- Check for request smuggling vulnerabilities using `smuggler`
- Perform `ffuf` using custom WordList based on the next SecLists [All.txt](https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt) and [fuzz-Bo0oM.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/fuzz-Bo0oM.txt) and [top10000.txt](https://github.com/danielmiessler/RobotsDisallowed/blob/master/top10000.txt)
- [WIP][x] Generate a HTML report in case of a vulnerable domain found.

The point is to get list of live IPs, attack available network protocols, check for common CVEs, perform directory bruteforce. Then use lists files to do manual analysis or create target-specific connect-back shellcode.

# Features

The project forked from original v1.0 [Jason Haddix](https://github.com/jhaddix/lazyrecon) and [Ben Sadeghipour](https://github.com/nahamsec/lazyrecon) aimed to implement some of the best practice like [Subdomain Takeovers](https://www.hackerone.com/blog/Guide-Subdomain-Takeovers), [TBHM](https://docs.google.com/presentation/d/1MWWXXRvvesWL8V-GiwGssvg4iDM58_RMeI_SZ65VXwQ), [Request Smuggling](https://portswigger.net/web-security/request-smuggling), [SSRF](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF), [LFI](https://www.allysonomalley.com/2021/02/11/burpparamflagger-identifying-possible-ssrf-lfi-insertion-points/) and [Bruteforce](https://danielmiessler.com/blog/the-most-interesting-disallowed-directories/) based on [Custom wordlist](https://www.youtube.com/watch?v=W4_QCSIujQ4&t=1237s&ab_channel=Nahamsec).


# Dependencies
Tested on `MacOS` and `Linux`
- To start use this script, please clone and/or setup the dependencies. You may copy each executable dependency to `/usr/local/bin/`, create symlinc like: `ln -s $HOME/smuggler/smuggler.py /usr/local/bin/smuggler`, or just export it to the PATH `export PATH=~/masscan/masscan:$PATH`.
- Config your own `HOMEUSER` and `ATTACKERURL` at the very top of the `lazyrecon.sh`.
- Use option `nuclei -update-templates` to get templates into `$HOME/nuclei-templates/` to use properly, but for LFI use [storenth-lfi](https://github.com/storenth/nuclei-templates/blob/master/vulnerabilities/other/storenth-lfi.yaml) forked till the time [projectdiscovery](https://github.com/projectdiscovery) introduce feature for dynamic replacement of parameters.
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
12. [massdns](https://github.com/blechschmidt/massdns)
13. [dnsx](https://github.com/projectdiscovery/dnsx)
14. [SecLists](https://github.com/danielmiessler/SecLists)
15. [httpx](https://github.com/projectdiscovery/httpx)
16. [nuclei](https://github.com/projectdiscovery/nuclei)
17. [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
18. [smuggler](https://github.com/storenth/requestsmuggler)
19. [ffuf](https://github.com/ffuf/ffuf)
20. [hydra](https://github.com/vanhauser-thc/thc-hydra)
21. [gf](https://github.com/tomnomnom/gf)
22. [unfurl](https://github.com/tomnomnom/unfurl)
23. [sqlmap](https://github.com/sqlmapproject/sqlmap)
24. [gospider](https://github.com/jaeles-project/gospider)
25. [hakrawler](https://github.com/hakluke/hakrawler)
26. [ssrf-headers-tool](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/ssrf.py)
27. [storenth-lfi](https://github.com/storenth/nuclei-templates/blob/master/vulnerabilities/other/storenth-lfi.yaml)



If you faced with some issues, feel free to join [Discord](https://discord.gg/fR2QVrWBTq), open PR or file the bug.

# Notes

 - Use [dnsperftest](https://github.com/cleanbrowsing/dnsperftest) to know your best resolvers
 - `Sublist3r` replaced with `subfinder` based on Twitter [discussion](https://twitter.com/Jhaddix/status/1293118260808843264)
 - `nmap` replaced with `masscan` based on its features and Twitter [duscussion](https://twitter.com/DanielMiessler/status/1286721113343447040)
 - `smuggler` forked from its [original](https://github.com/gwen001/pentest-tools/blob/master/smuggler.py) aimed to get lightweight solution included this [PR](https://github.com/gwen001/pentest-tools/pull/10)
 - ~~`grep` `meg`'s output for [Location](https://twitter.com/hunter0x7/status/1293168500672954368) in order to exclude 301/302 status codes~~
 (replaced with `httpx -fc 301,302` approach)
 - ~~`httpx -ip` used without `dnsprobe` based on @pdiscoveryio Twitter [answer](https://twitter.com/pdiscoveryio/status/1338163970557894656)~~
 - `altdns` used based on [Scrutiny on the bug bounty](https://docs.google.com/presentation/d/1PCnjzCeklOeGMoWiE2IUzlRGOBxNp8K5hLQuvBNzrFY/)
 - WIP: you can track activity in Projects To Do board

# Open Questions

- Investigate ANS like `amass intel -org 'MAILRU'` and pass it to `amass enum -d mail.ru -asn 12345` gives us more subdomains? (Or get list of ASN using `echo 'MAILRU' | metabigor net --org -v` or just manually get it through http://bgp.he.net). If yes positional arguments will be invoked just like:
```bash
./lazyrecon.sh tesla.com 12345
```
- Connect-back shellcode automation with simpest fuzzer implementation? Like:
```bash
cat /dev/urandom | nc hostname port
```


**Acknowledgement:** This code was created for personal use with hosts you able to hack/explore by any of the known bug bounty program. Use it at your own risk.

# Methodology
1. Run `./lazyrecon.sh`
2. Google dorking
3. Trello, Atlassian, Github, Bitbucket dorking
4. Check JS sources for credentials, API endpoints, debug for variables
5. Check `XHR` API requests, fuzz parameters
6. RCE based on exploit-db.com for known target-specific CVE service version, deserialization, SQLi, File upload, LFI, SSRF
7. Brute dirsearch: fuzbo0oM-top10000 --> raft --> target specific
8. Continue brute with custom Headers (X-Custom-IP-Authorization: 127.0.0.1; X-Original-URL:)
9. Start new brute with POST method
10. Try bypass 401/403 errors using [notable](https://github.com/filedescriptor/Unicode-Mapping-on-Domain-names) methods (`%23`, `/%2e/`, `admin.php%2500.md` etc)
11. `wireshark`/`tcpdump` for plain http while login (missing ssl)
12. `hydra`, 21, 22, 25 ports
13. XSS [xsscrapy.py](https://github.com/DanMcInerney/xsscrapy) or [XSSTRON](https://github.com/RenwaX23/XSSTRON)
14. Run `./lazyrecon.sh` using ASN --> cidr

# Notable articles
1. IDOR: https://www.aon.com/cyber-solutions/aon_cyber_labs/finding-more-idors-tips-and-tricks/?utm_source=newsletter&utm_medium=email&utm_campaign=bug_bytes_110_scope_based_recon_finding_more_idors_how_to_hack_sharepoint&utm_term=2021-02-17
2. SSRF: https://notifybugme.medium.com/finding-ssrf-by-full-automation-7d2680091d68 and https://rez0.blog/hacking/2019/11/29/rce-via-imagetragick.html