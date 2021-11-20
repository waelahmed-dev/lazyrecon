# Notes
 - `aquatone` replaced by [headless chromium async script](https://github.com/storenth/lazyrecon/compare/0a9c4c586ee4...24c35f9cadd0) based on performance
 - `Sublist3r` replaced with `subfinder` based on Twitter [discussion](https://twitter.com/Jhaddix/status/1293118260808843264)
 - `nmap` replaced with `masscan` based on its features and Twitter [duscussion](https://twitter.com/DanielMiessler/status/1286721113343447040), use `helpers/nmap_nse_ifile.sh` by hands using `masscan_output.gnmap` as input
 - `smuggler` forked from its [original](https://github.com/gwen001/pentest-tools/blob/master/smuggler.py) aimed to get lightweight solution included this [PR](https://github.com/gwen001/pentest-tools/pull/10)
 - ~~`grep` `meg`'s output for [Location](https://twitter.com/hunter0x7/status/1293168500672954368) in order to exclude 301/302 status codes
 (replaced with `httpx -fc 301,302` approach)~~
 - ~~`httpx -ip` used without `dnsprobe` based on @pdiscoveryio Twitter [answer](https://twitter.com/pdiscoveryio/status/1338163970557894656)~~
 - `altdns` used based on [Scrutiny on the bug bounty](https://docs.google.com/presentation/d/1PCnjzCeklOeGMoWiE2IUzlRGOBxNp8K5hLQuvBNzrFY/)
 - ~~`massdns` fully replaced with `shuffledns` because of [issue](https://github.com/blechschmidt/massdns/issues/73)~~
 - `shuffledns` replaced with `puredns` based on performance
 - [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data)
 - local listen server approach replaced with [interactsh](https://github.com/projectdiscovery/interactsh)
 - LFI payload now handled and fully featured by [LFI-Payload-List](https://github.com/storenth/LFI-Payload-List) caused outdated [LFI-Payload-List](https://github.com/emadshanab/LFI-Payload-List)
 - WIP: you can track activity in Projects To Do board
 