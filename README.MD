```
  _
 | | __ _ ____ _   _ _ __ ___  ___  ___  _ __
 | |/ _  |_  /| | | |  __/ _ \/ __|/ _ \|  _ \
 | | (_|  / / | | | | | |  __/ (__  (_) | | | 
 |_|\__ _|___/ \__  |_|  \___|\___|\___/|_| |_
               |___/
```

# Usage

`./lazyrecon.sh target.com`

# About

This script is intended to automate your reconnaissance process in an organized fashion by performing the following:

- Create a dated folder with recon notes for target
- Grab subdomains using `Sublist3r`
- Filtering out live subdomains from a list of hosts using `host`
- Filtering out for working http and https servers using `meg`
- Grab the response and sieving through
- Check for request smuggling vulnerabilities using `smuggler`
- [WIP][x] Perform `nmap` on live servers
- [WIP][x] Perform `dirsearch`
- Generate a HTML report in case of a vulnerable domain found.

# Features

The project forked from original v1.0 [Jason Haddix](https://github.com/jhaddix/lazyrecon) and [Ben Sadeghipour](https://github.com/nahamsec/lazyrecon) aimed to implement some of the best practice like [Subdomain Takeovers](https://www.hackerone.com/blog/Guide-Subdomain-Takeovers), [Bruteforce](https://github.com/jhaddix/tbhm) and [Request Smuggling](https://portswigger.net/web-security/request-smuggling)


# Dependencies

To start use this script, please clone and setup the next tools in the same level (near the lazyrecon directory).
For example:
```bash
~/lazyrecon
~/Sublist3r
~/dirsearch
~/meg
~/httprobe
~/smuggler
```
Make sure all tools correctly installed and enabled with execute permissions: `chmod +x`
1. [Sublist3r](https://github.com/aboul3la/Sublist3r)
2. [dirsearch](https://github.com/maurosoria/dirsearch)
3. [meg](https://github.com/tomnomnom/meg)
4. [httprobe](https://github.com/tomnomnom/httprobe)
5. [smuggler](https://github.com/storenth/requestsmuggler)

If you faced with some issues, feel free to open PR/bug or just reach me out.

**Acknowledgement:** This code was created for personal use with hosts you able to hack/explore by any of the known bug bounty program. Use it at your own risk.
