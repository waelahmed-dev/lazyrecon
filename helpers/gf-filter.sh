#!/bin/bash

# https://github.com/tomnomnom/gf/issues/55
filter(){
    echo
    gf ssrf $1 | uniq > $2
}

filter "$@"