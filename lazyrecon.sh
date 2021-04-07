#!/bin/bash

# rewrite as &> file and then parse
./lazyrecon-main.sh $@ 2> lazylog

if [[ "$?" == "0" ]]; then
    ./discord-hook.sh "[info] $1 done"
  else
    stats=(tail -n 1 lazylog)
    ./discord-hook.sh "[error] $stats"
fi
