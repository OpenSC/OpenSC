# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in
DISTCLEANFILES = opensc.conf scldap.conf
EXTRA_DIST = opensc.conf.in scldap.conf.in

noinst_DATA = opensc.conf.in scldap.conf.in opensc.conf scldap.conf

%: %.in
	sed -e "s#PKGDATADIR#$(shell eval echo $(pkgdatadir))#" < $^ > $@
