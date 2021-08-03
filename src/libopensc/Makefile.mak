TOPDIR = ..\..

TARGET                  = opensc.dll opensc_a.lib
OBJECTS			= \
	sc.obj ctx.obj log.obj errors.obj \
	asn1.obj base64.obj sec.obj card.obj iso7816.obj dir.obj ef-atr.obj \
	ef-gdo.obj padding.obj apdu.obj simpletlv.obj gp.obj \
	\
	pkcs15.obj pkcs15-cert.obj pkcs15-data.obj pkcs15-pin.obj \
	pkcs15-prkey.obj pkcs15-pubkey.obj pkcs15-skey.obj \
	pkcs15-sec.obj pkcs15-algo.obj pkcs15-cache.obj pkcs15-syn.obj \
	\
	muscle.obj muscle-filesystem.obj \
	\
	ctbcs.obj reader-ctapi.obj reader-pcsc.obj reader-openct.obj reader-tr03119.obj \
	\
	card-setcos.obj card-flex.obj card-gpk.obj \
	card-cardos.obj card-tcos.obj card-default.obj \
	card-mcrd.obj card-starcos.obj card-openpgp.obj \
	card-oberthur.obj card-belpic.obj card-atrust-acos.obj \
	card-entersafe.obj card-epass2003.obj card-coolkey.obj \
	card-incrypto34.obj card-cac.obj card-cac1.obj card-cac-common.obj \
	card-piv.obj card-muscle.obj \
	card-asepcos.obj card-akis.obj card-gemsafeV1.obj card-rutoken.obj \
	card-rtecp.obj card-westcos.obj card-myeid.obj \
	card-itacns.obj card-authentic.obj \
	card-iasecc.obj iasecc-sdo.obj iasecc-sm.obj cwa-dnie.obj cwa14890.obj \
	card-sc-hsm.obj card-dnie.obj card-isoApplet.obj pkcs15-coolkey.obj \
	card-masktech.obj card-gids.obj card-jpki.obj \
	card-npa.obj card-esteid2018.obj card-idprime.obj \
	card-edo.obj \
	\
	pkcs15-openpgp.obj pkcs15-starcert.obj pkcs15-cardos.obj \
	pkcs15-tcos.obj pkcs15-esteid.obj pkcs15-gemsafeGPK.obj \
	pkcs15-actalis.obj pkcs15-atrust-acos.obj pkcs15-tccardos.obj pkcs15-piv.obj \
	pkcs15-cac.obj pkcs15-esinit.obj pkcs15-westcos.obj pkcs15-pteid.obj pkcs15-din-66291.obj \
	pkcs15-oberthur.obj pkcs15-itacns.obj pkcs15-gemsafeV1.obj pkcs15-sc-hsm.obj \
	pkcs15-dnie.obj pkcs15-gids.obj pkcs15-iasecc.obj pkcs15-jpki.obj \
	pkcs15-esteid2018.obj pkcs15-idprime.obj \
	compression.obj p15card-helper.obj sm.obj \
	aux-data.obj \
	$(TOPDIR)\win32\versioninfo.res
LIBS = $(TOPDIR)\src\scconf\scconf.lib \
	   $(TOPDIR)\src\common\common.lib \
	   $(TOPDIR)\src\common\libscdl.lib \
	   $(TOPDIR)\src\ui\strings.lib \
	   $(TOPDIR)\src\ui\notify.lib \
	   $(TOPDIR)\src\sm\libsmiso.lib \
	   $(TOPDIR)\src\sm\libsmeac.lib \
	   $(TOPDIR)\src\pkcs15init\pkcs15init.lib

all: $(TOPDIR)\win32\versioninfo.res $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

opensc.dll: $(OBJECTS) $(LIBS)
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type lib$*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:opensc.dll $(OBJECTS) $(LIBS) $(OPENPACE_LIB) $(OPENSSL_LIB) $(ZLIB_LIB) gdi32.lib Comctl32.lib Shell32.lib user32.lib advapi32.lib ws2_32.lib
	if EXIST opensc.dll.manifest mt -manifest opensc.dll.manifest -outputresource:opensc.dll;2

opensc_a.lib: $(OBJECTS)
	lib $(LIBFLAGS) /out:opensc_a.lib $(OBJECTS)
