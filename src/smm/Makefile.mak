TOPDIR = ..\..

TARGET = smm-local.dll

OBJECTS = smm-local.obj sm-global-platform.obj sm-cwa14890.obj sm-card-iasecc.obj sm-card-authentic.obj

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS) ..\libsm\libsm.lib ..\libopensc\opensc.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link /dll $(LINKFLAGS) /def:$*.def /out:$(TARGET) $(OBJECTS) ..\libsm\libsm.lib ..\libopensc\opensc_a.lib $(ZLIB_LIB) $(OPENSSL_LIB) ..\common\libscdl.lib ws2_32.lib gdi32.lib advapi32.lib Crypt32.lib User32.lib
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2

.c.obj:
	cl $(COPTS) /c $<
