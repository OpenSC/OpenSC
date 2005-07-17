#!/bin/bash

set -e

export SERVER=http://www.opensc.org
export WIKI=opensc/wiki
export XSL=export-wiki.xsl

test -f `basename $0`

rm -rf *.html *.css

wget $SERVER/$WIKI/TitleIndex -O TitleIndex.tmp

grep "\"/$WIKI/[^\"]*\"" TitleIndex.tmp \
        |sed -e "s#.*\"/$WIKI/\([^\"]*\)\".*#\1#g" \
	> WikiWords.tmp
sed -e /^Trac/d -e /^Wiki/d -e /^TitleIndex/d -e /^RecentChanges/d \
	-e /^CamelCase/d -e /^SandBox/d -i WikiWords.tmp

for A in WikiStart `cat WikiWords.tmp`
do
	F=`echo $A|sed -e 's/\//_/g'`
	wget $SERVER/$WIKI/$A  -O $F.tmp
	xsltproc --output $F.html $XSL $F.tmp
	sed -e "s#<a href=\"/$WIKI/\([^\"]*\)\"#<a href=\"\1.html\"#g" \
		-i $F.html
done

mv WikiStart.html index.html

wget http://www.opensc.org/trac/css/trac.css

rm *.tmp
