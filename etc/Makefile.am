# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in
DISTCLEANFILES = opensc.conf 
EXTRA_DIST = opensc.conf.in 

noinst_DATA = opensc.conf.in opensc.conf 

%: %.in
	sed -e "s#PKGDATADIR#$(shell eval echo $(pkgdatadir))#" < $^ > $@
