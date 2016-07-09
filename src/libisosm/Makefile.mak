TOPDIR = ..\..

TARGET = libisosm.lib
OBJECTS = iso-sm.obj

all: $(TARGET)

$(TARGET): $(OBJECTS)
        lib $(LIBFLAGS) /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak
