TOPDIR = ..\..


TARGET                  = opensc.dll opensc_a.lib

HEADERS			= \
	asn1.h cardctl.h cards.h emv.h errors.h \
	log.h opensc.h pkcs15.h types.h ui.h

HEADERSDIR		= $(TOPDIR)\src\include\opensc

OBJECTS			= \
	sc.obj ctx.obj ui.obj log.obj errors.obj \
	asn1.obj base64.obj sec.obj card.obj iso7816.obj dir.obj padding.obj apdu.obj \
	\
	pkcs15.obj pkcs15-cert.obj pkcs15-data.obj pkcs15-pin.obj \
	pkcs15-prkey.obj pkcs15-pubkey.obj pkcs15-sec.obj \
	pkcs15-wrap.obj pkcs15-algo.obj pkcs15-cache.obj pkcs15-syn.obj \
	pkcs15-gemsafeV1.obj \
	\
	emv.obj muscle.obj muscle-filesystem.obj \
	\
	ctbcs.obj reader-ctapi.obj reader-pcsc.obj reader-openct.obj \
	\
	card-setcos.obj card-miocos.obj card-flex.obj card-gpk.obj \
	card-cardos.obj card-tcos.obj card-emv.obj card-default.obj \
	card-mcrd.obj card-starcos.obj card-openpgp.obj card-jcop.obj \
	card-oberthur.obj card-belpic.obj card-atrust-acos.obj card-entersafe.obj \
	card-incrypto34.obj card-piv.obj card-muscle.obj card-acos5.obj \
	card-asepcos.obj card-akis.obj card-gemsafeV1.obj card-rutoken.obj \
	card-rtecp.obj card-westcos.obj card-myeid.obj \
	\
	p15emu-westcos.obj \
	pkcs15-openpgp.obj pkcs15-infocamere.obj pkcs15-starcert.obj \
	pkcs15-tcos.obj pkcs15-esteid.obj pkcs15-postecert.obj pkcs15-gemsafeGPK.obj \
	pkcs15-actalis.obj pkcs15-atrust-acos.obj pkcs15-tccardos.obj pkcs15-piv.obj \
	pkcs15-esinit.obj \
	compression.obj p15card-helper.obj \
	versioninfo.res

all: versioninfo.res install-headers $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

opensc.dll: $(OBJECTS) ..\scconf\scconf.lib ..\common\common.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type lib$*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:opensc.dll $(OBJECTS) ..\scconf\scconf.lib ..\common\common.lib winscard.lib $(OPENSSL_LIB) $(ZLIB_LIB) $(ICONV_LIB) gdi32.lib $(LIBLTDL_LIB) advapi32.lib ws2_32.lib
	if EXIST opensc.dll.manifest mt -manifest opensc.dll.manifest -outputresource:opensc.dll;2

opensc_a.lib: $(OBJECTS) ..\scconf\scconf.lib ..\common\common.lib
	lib $(LIBFLAGS) /out:opensc_a.lib $(OBJECTS) ..\scconf\scconf.lib ..\common\common.lib winscard.lib user32.lib
