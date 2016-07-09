TOPDIR = ..\..

TARGET = cardnpa.dll
OBJECTS = card-npa.obj

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS) ..\libsceac\libsceac.lib ..\libopensc\opensc_a.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link /dll $(LINKFLAGS) /def:$*.def /implib:$*.lib /out:$(TARGET) $(OBJECTS) ..\libsceac\libsceac.lib ..\libopensc\opensc_a.lib ..\common\common.lib ..\common\libscdl.lib $(ZLIB_LIB) $(OPENPACE_LIB) $(OPENSSL_LIB) ws2_32.lib gdi32.lib advapi32.lib Crypt32.lib User32.lib
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2
