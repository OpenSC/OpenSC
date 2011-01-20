TOPDIR = ..\..

TARGET = opensc-cardmod.dll
OBJECTS = cardmod.obj 

all: $(TARGET)

$(TARGET): $(OBJECTS)
	link /dll /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS) ..\libopensc\opensc.lib gdi32.lib advapi32.lib winscard.lib Crypt32.lib User32.lib
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

