```
  _
 | | __ _ ____ _   _ _ __ ___  ___  ___  _ __
 | |/ _  |_  /| | | |  __/ _ \/ __|/ _ \|  _ \
 | | (_|  / / | | | | | |  __/ (__  (_) | | | 
 |_|\__ _|___/ \__  |_|  \___|\___|\___/|_| |_
               |___/
```

# Usage beta

Execute with `sudo` because of `masscan`

`./lazyrecon.sh target.com`

# About

This script is intended to automate your reconnaissance process in an organized fashion by performing the following:

- Create a dated folder with recon notes for target
- Grab subdomains using `subfinder`
- Subdomain discovery through alterations and permutations using `altdns`
- Filtering out live subdomains from a list of hosts using `host`
- Filtering out for working http and https servers using `meg`
- Grab the response and sieving through to exclude false-positives such us `Location` headers
- Check for request smuggling vulnerabilities using `smuggler`
- Perform `masscan` on live servers using `dnmasscan`
- Automatically brute-forces services with default credentials using `Medusa`
- [WIP][x] Perform `dirsearch` using custom WordList based on the next SecLists [All.txt](https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt) and [fuzz-Bo0oM.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/fuzz-Bo0oM.txt)
- [WIP][x] Generate a HTML report in case of a vulnerable domain found.

# Features

The project forked from original v1.0 [Jason Haddix](https://github.com/jhaddix/lazyrecon) and [Ben Sadeghipour](https://github.com/nahamsec/lazyrecon) aimed to implement some of the best practice like [Subdomain Takeovers](https://www.hackerone.com/blog/Guide-Subdomain-Takeovers), [Bruteforce](https://github.com/jhaddix/tbhm) and [Request Smuggling](https://portswigger.net/web-security/request-smuggling).


# Dependencies

To start use this script, please clone and setup the next tools in the same level (near the lazyrecon directory).
For example:
```bash
~/lazyrecon
~/subfinder
~/altdns
~/dirsearch
~/meg
~/httprobe
~/smuggler
~/masscan
~/dnmasscan
~/brutespray
```
Make sure all tools correctly installed and enabled with execute permissions: `chmod +x`
1. [subfinder](https://github.com/projectdiscovery/subfinder)
2. [altdns](https://github.com/infosec-au/altdns)
3. [dirsearch](https://github.com/maurosoria/dirsearch)
4. [meg](https://github.com/tomnomnom/meg)
5. [httprobe](https://github.com/tomnomnom/httprobe)
6. [smuggler](https://github.com/storenth/requestsmuggler)
7. [masscan](https://github.com/robertdavidgraham/masscan)
8. [dnmasscan](https://github.com/rastating/dnmasscan)
9. [brutespray](https://github.com/storenth/brutespray)

If you faced with some issues, feel free to open PR or bug.

# Notes

 - `Sublist3r` replaced with `subfinder` based on Twitter [discussion](https://twitter.com/Jhaddix/status/1293118260808843264)
 - `nmap` replaced with `masscan` based on its features
 - `smuggler` forked from its [original](https://github.com/gwen001/pentest-tools/blob/master/smuggler.py) aimed to get lightweight solution included this [PR](https://github.com/gwen001/pentest-tools/pull/10)
 - `grep` `meg`'s output for [Location](https://twitter.com/hunter0x7/status/1293168500672954368) in order to exclude 301/302 status codes
 - `altdns` used based on [Scrutiny on the bug bounty](https://docs.google.com/presentation/d/1PCnjzCeklOeGMoWiE2IUzlRGOBxNp8K5hLQuvBNzrFY/)
 - WIP: you can track activity in Projects To Do board

**Acknowledgement:** This code was created for personal use with hosts you able to hack/explore by any of the known bug bounty program. Use it at your own risk.
