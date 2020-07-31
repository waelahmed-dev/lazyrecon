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
- Grab the response header
- Perform `nmap` for live servers
- Perform `dirsearch`
- Generate a HTML report with output from the tools above

# Dependencies

To start use this script, please clone and setup the next tools in the same level (near the lazyrecon directory).
For example:
```bash
~/lazyrecon
~/Sublist3r
~/dirsearch
~/meg
~/httprobe
```
Make sure all tools coreclty installed and enabled with execution permissions: `chmod +x`
1. [Sublist3r](https://github.com/aboul3la/Sublist3r)
2. [dirsearch](https://github.com/maurosoria/dirsearch)
3. [meg](https://github.com/tomnomnom/meg)
4. [httprobe](https://github.com/tomnomnom/httprobe)

If you faced with some issue, feel free to open PR/bug or just reach me out.

**Acknowledgement:** This code was created for personal use with hosts you able to hack/explore by any of the known bug bounty program. Use it at your own risk.
