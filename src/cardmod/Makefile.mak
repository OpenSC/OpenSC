TOPDIR = ..\..

TARGET = opensc-cardmod.dll
OBJECTS = cardmod.obj 

all: $(TARGET)

$(TARGET): $(OBJECTS)
	link /dll /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS) ..\libopensc\opensc.lib gdi32.lib advapi32.lib winscard.lib Crypt32.lib User32.lib

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

