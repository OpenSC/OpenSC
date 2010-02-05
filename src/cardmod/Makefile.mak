TOPDIR = ..\..

TARGET = opensc-cardmod.lib
OBJECTS = cardmod.obj 

all: $(TARGET)

$(TARGET): $(OBJECTS)
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

