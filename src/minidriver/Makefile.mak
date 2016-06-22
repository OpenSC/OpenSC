TOPDIR = ..\..

TARGET = opensc-minidriver.dll
OBJECTS = minidriver.obj versioninfo-minidriver.res
LIBS = $(TOPDIR)\src\libopensc\opensc_a.lib \
	   $(TOPDIR)\src\pkcs15init\pkcs15init.lib \
	   $(TOPDIR)\src\common\libscdl.lib

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS) $(LIBS)
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type minidriver.exports >> $*.def
	link /dll $(LINKFLAGS) /def:$*.def /out:$(TARGET) $(OBJECTS) $(LIBS) $(ZLIB_LIB) $(OPENSSL_LIB) ws2_32.lib gdi32.lib advapi32.lib Crypt32.lib User32.lib bcrypt.lib DelayImp.lib Rpcrt4.lib /DELAYLOAD:bcrypt.dll
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2
