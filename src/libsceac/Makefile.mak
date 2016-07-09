TOPDIR = ..\..

TARGET = libsceac.lib
OBJECTS = sc-eac.obj rw_sfid.obj

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS)
        lib $(LIBFLAGS) /out:$(TARGET) $(OBJECTS)
