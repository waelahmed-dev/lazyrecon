```
  _
 | | __ _ ____ _   _ _ __ ___  ___  ___  _ __
 | |/ _  |_  /| | | |  __/ _ \/ __|/ _ \|  _ \
 | | (_|  / / | | | | | |  __/ (__  (_) | | | 
 |_|\__ _|___/ \__  |_|  \___|\___|\___/|_| |_
               |___/
```

# Usage
Execute with `sudo` because of `masscan`:
```bash
sudo ./lazyrecon.sh target.com
```
Force with options: `alt` (permutate subdomains), `brute` (directory bruteforce). `mad` mode uses wayback machine and merge subdomains and paths with corresponding wordlists to get the best out of it: 
```bash
sudo ./lazyrecon.sh target.com --mad --alt
```

# About

This script is intended to automate your reconnaissance process in an organized fashion by performing the following:

- Create a dated folder with recon notes for target
- Grab subdomains using `subfinder`, `amass`, `assetfinder` and wayback machines `gau`, `waybackurls`
- Subdomain discovery through alterations and permutations using `altdns`
- Filtering out live subdomains from a list of hosts using `massdns`
- Perform `masscan` on live servers
- Automatically brute-forces services with default credentials using `hydra` and `brutespray`
- Check http probes using `httpx`
- Scanning for known paths and CVEs using `nuclei`
- Check for request smuggling vulnerabilities using `smuggler`
- Perform `ffuf` using custom WordList based on the next SecLists [All.txt](https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt) and [fuzz-Bo0oM.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/fuzz-Bo0oM.txt) and [top10000.txt](https://github.com/danielmiessler/RobotsDisallowed/blob/master/top10000.txt)
- [WIP][x] Generate a HTML report in case of a vulnerable domain found.

The point is to get list of live IPs, attack available network protocols, check for common CVEs, perform directory bruteforce. Then use lists files to do manual analysis or create target-specific connect-back shellcode.

# Features

The project forked from original v1.0 [Jason Haddix](https://github.com/jhaddix/lazyrecon) and [Ben Sadeghipour](https://github.com/nahamsec/lazyrecon) aimed to implement some of the best practice like [Subdomain Takeovers](https://www.hackerone.com/blog/Guide-Subdomain-Takeovers), [TBHM](https://docs.google.com/presentation/d/1MWWXXRvvesWL8V-GiwGssvg4iDM58_RMeI_SZ65VXwQ), [Request Smuggling](https://portswigger.net/web-security/request-smuggling), and [Bruteforce](https://danielmiessler.com/blog/the-most-interesting-disallowed-directories/) based on [Custom wordlist](https://www.youtube.com/watch?v=W4_QCSIujQ4&t=1237s&ab_channel=Nahamsec).


# Dependencies

To start use this script, please clone and setup the next tools in the same level (near the lazyrecon directory). Next, you may copy each executable dependency to `cp ~/smuggler/smuggler.py /usr/local/bin/` or just export it to the PATH `export PATH=~/masscan/masscan:$PATH`

```bash
~/lazyrecon/
~/subfinder/
~/assetfinder/
~/waybackurls/
~/gau/
~/altdns/
~/masscan/
~/massdns/
~/dnsx/
~/unfurl/
~/httpx/
~/nuclei/
~/nuclei-templates/
~/brutespray/
~/hydra
~/smuggler/
~/ffuf/
```
Make sure all tools correctly installed and enabled with execute permissions: `chmod +x`
1. [subfinder](https://github.com/projectdiscovery/subfinder)
2. [assetfinder](https://github.com/tomnomnom/assetfinder)
3. [waybackurls](https://github.com/tomnomnom/waybackurls)
4. [gau](https://github.com/lc/gau)
5. [altdns](https://github.com/infosec-au/altdns)
6. [unfurl](https://github.com/tomnomnom/unfurl)
7. [masscan](https://github.com/robertdavidgraham/masscan)
8. [massdns](https://github.com/blechschmidt/massdns)
9. [dnsx](https://github.com/projectdiscovery/dnsx)
10. [brutespray](https://github.com/storenth/brutespray)
11. [hydra](https://github.com/vanhauser-thc/thc-hydra)
12. [httpx](https://github.com/projectdiscovery/httpx)
13. [nuclei](https://github.com/projectdiscovery/nuclei)
14. [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
15. [smuggler](https://github.com/storenth/requestsmuggler)
16. [ffuf](https://github.com/ffuf/ffuf)

If you faced with some issues, feel free to open PR or file the bug.

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
./lazyrecon.sh target.com 12345
```
- Connect-back shellcode automation with simpest fuzzer implementation? Like:
```bash
cat /dev/urandom | nc hostname port
```


**Acknowledgement:** This code was created for personal use with hosts you able to hack/explore by any of the known bug bounty program. Use it at your own risk.
