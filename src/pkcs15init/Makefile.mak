TOPDIR = ..\..

TARGET = pkcs15init.dll

HEADERS = pkcs15-init.h profile.h keycache.h
HEADERSDIR = $(TOPDIR)\src\include\opensc

OBJECTS = pkcs15-lib.obj profile.obj keycache.obj \
          pkcs15-gpk.obj pkcs15-miocos.obj pkcs15-cflex.obj \
          pkcs15-cardos.obj pkcs15-jcop.obj pkcs15-starcos.obj \
          pkcs15-oberthur.obj pkcs15-setcos.obj pkcs15-incrypto34.obj \
          pkcs15-muscle.obj pkcs15-asepcos.obj pkcs15-rutoken.obj \
          pkcs15-entersafe.obj pkcs15-rtecp.obj pkcs15-westcos.obj \
	  pkcs15-myeid.obj \
          versioninfo.res

all: install-headers $(TARGET) 

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS)
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) $(OBJECTS) ..\scconf\scconf.lib ..\common\common.lib ..\libopensc\opensc.lib winscard.lib $(OPENSSL_LIB) gdi32.lib $(LIBLTDL_LIB)
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2
