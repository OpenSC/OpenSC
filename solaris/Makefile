PACKAGE=OSCopensc
PACKAGE_NAME=opensc
VERSION=CVS
PWD=pwd
CONFIGURE_PREFIX=$(PWD:sh)/..
CONFIGURE=${CONFIGURE_PREFIX}/configure
CONFIGURE_ARGS=--prefix=/usr --sysconfdir=/etc/opensc --mandir=/usr/share/man --enable-pcsc --enable-openct
CONFIG_GUESS=${CONFIGURE_PREFIX}/config.guess
UNAME_ARCH=/usr/bin/uname -p
PLATFORM = $(CONFIG_GUESS:sh)
ARCH = $(UNAME_ARCH:sh)

build:
	@echo "Setup platform specific build directory build-${PLATFORM}"
	mkdir -p build-${PLATFORM}
	( cd build-${PLATFORM}; CC=cc PCSC_CFLAGS=-I/usr/include/smartcard ${CONFIGURE} ${CONFIGURE_ARGS}; make )

dist:
	@echo "Setup platform specific dist directory dist-${PLATFORM}"
	mkdir -p dist-${PLATFORM}
	@echo "Performing Installing in dist directory"
	( cd build-${PLATFORM}; make DESTDIR=`pwd`/../dist-${PLATFORM} install )
package:
	@echo "Setup package meta files"
	-cp proto dist-${PLATFORM}
	-sed "s|@ARCH@|${ARCH}|" <checkinstall.in >dist-${PLATFORM}/checkinstall
	-sed	-e "s|@ARCH@|${ARCH}|" \
		-e "s|@VERSION@|${VERSION}|" \
		-e "s|@PACKAGE@|${PACKAGE}|" \
		-e "s|@PACKAGE_NAME@|${PACKAGE_NAME}|" \
		<pkginfo.in >dist-${PLATFORM}/pkginfo
	mkdir -p dist-${PLATFORM}/etc/opensc
	-cp opensc.conf-dist dist-${PLATFORM}/etc/opensc/opensc.conf
	@echo "Creating package"
	( \
		cd dist-${PLATFORM}; \
		pkgmk -o -r . -d . -f proto; \
		pkgtrans -s . ../OSCopensc-${VERSION}-${PLATFORM}.pkg ${PACKAGE} \
	)
