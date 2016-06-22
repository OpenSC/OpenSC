TOPDIR = ..\..

TARGET = smm-local.dll

OBJECTS = smm-local.obj sm-global-platform.obj sm-cwa14890.obj sm-card-iasecc.obj sm-card-authentic.obj
LIBS = $(TOPDIR)\src\libsm\libsm.lib $(TOPDIR)\src\libopensc\opensc_a.lib $(TOPDIR)\src\common\libscdl.lib

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"
$(TARGET): $(OBJECTS) $(LIBS)
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link /dll $(LINKFLAGS) /def:$*.def /out:$(TARGET) $(OBJECTS) $(LIBS) $(ZLIB_LIB) $(OPENSSL_LIB) ws2_32.lib gdi32.lib advapi32.lib Crypt32.lib User32.lib
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2

!ELSE
$(TARGET):

!ENDIF
