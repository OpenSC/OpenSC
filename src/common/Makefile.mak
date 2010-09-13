TOPDIR = ..\..

TARGET = common.lib
OBJECTS = compat_getpass.obj compat_getopt.obj compat_strlcpy.obj compat_strlcat.obj simclist.obj

all: $(TARGET)

$(TARGET): $(OBJECTS)
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

