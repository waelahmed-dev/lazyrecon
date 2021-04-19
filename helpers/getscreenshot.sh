#!/bin/bash -x

# get page and take screenshot
# https://developers.google.com/web/updates/2017/04/headless-chrome#screenshots

# SCOPE=$(echo $1 | awk -F '//' '{print $NF}')
SCOPE=$(echo $1 | grep -oriahE "(([[:alpha:][:digit:]-]+\.)+)?[[:alpha:][:digit:]-]+\.[[:alpha:]]{2,5}([:][[:digit:]]{2,4})?" | sed "s/:/_/;s/[.]/_/g")
chromium --headless --disable-gpu --window-size=1280,720 --screenshot="${SCOPE}.png" $1
