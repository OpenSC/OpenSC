#!/bin/bash

set -ex -o xtrace

BUILDPATH=${PWD}
BRANCH="`git log --max-count=1 --date=short --abbrev=8 --pretty=format:"%cd_%h"`"

git clone --single-branch https://${GH_TOKEN}@github.com/OpenSC/Nightly.git > /dev/null 2>&1
cd Nightly
git checkout -b "${BRANCH}"

for file in ${BUILDPATH}/win32/Output/OpenSC*.exe ${BUILDPATH}/opensc*.tar.gz ${BUILDPATH}/OpenSC*.dmg ${BUILDPATH}/OpenSC*.msi ${BUILDPATH}/OpenSC*.zip
do
    if [ -f ${file} ]
    then
        # github only allows a maximum file size of 50MB
        MAX_MB_FILESIZE=50
        if [ $(du -m "$file" | cut -f 1) -ge $MAX_MB_FILESIZE ]
        then
            split -b ${MAX_MB_FILESIZE}m ${file} `basename ${file}`.
        else
            cp ${file} .
        fi
        git add `basename ${file}`*
    fi
done

git commit --message "$1"
i=0
while [ $i -le 10 ] && ! git push --quiet --set-upstream origin "${BRANCH}"
do
    sleep $[ ( $RANDOM % 32 )  + 1 ]s
    git pull --rebase origin --strategy-option ours "${BRANCH}"
    i=$(( $i + 1 ))
done
