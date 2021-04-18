#!/bin/bash
# Script create HTML report
# invokation: ./report.sh "my.games" "/Users/storenth/lazytargets/my.games/recon-21-04-18_23-16-43"


# Variables
TITLE="Security report for $1"
TARGETDIR=$2
CURRENT_TIME=$(date +"%x %r %Z")
TIME_STAMP="Generated $CURRENT_TIME, by $USER"
INVOKATION=$(cat ${TARGETDIR}/_call_params.txt)

# Images
images() {
    echo '<div>'
    for line in ${TARGETDIR}/screenshots/*; do
        FILENAME=$(basename $line | sed 's/[.]png//')
        URL=$(echo "${FILENAME}" | sed -E 's/^(.*)_/\1\:/; s/_/./g')
        echo "<p>${URL}</p>"
        echo "<img src=${line} width=400px height=auto alt=${URL}>"
        technote=$(grep $URL ${TARGETDIR}/nuclei/nuclei_output_technology.txt)
        echo "<p>$technote</p>"
    done
    echo '</div>'
}

# based on nuclei
technologies() {
    echo '<div>'
    for line in ${TARGETDIR}/screenshots/*; do
        FILENAME=$(basename $line | sed 's/[.]png//')
        URL=$(echo "${FILENAME}" | sed -E 's/^(.*)_/\1\:/; s/_/./g')
        technote=$(grep $URL ${TARGETDIR}/nuclei/nuclei_output_technology.txt)
        echo $technote
    done
    echo '</div>'
}


# Main entry point
echo "<!DOCTYPE html>
<HTML lang=en>
        <HEAD>
                <meta charset="UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <TITLE>$TITLE</TITLE>
        </HEAD>
        <BODY>
                <p>Invoked by <a href=https://github.com/storenth/lazyrecon>lazyrecon v2.0</a>with next parameters: $INVOKATION</p>
                <H1>$TITLE</H1>
                <P>$TIME_STAMP</P>
"

images

echo "</BODY>
</HTML>
"
