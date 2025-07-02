TOPDIR = ..\..

TARGET = libsm.lib
OBJECTS = sm-common.obj

TARGET1 = libsmiso.lib
OBJECTS1 = sm-iso.obj

TARGET2 = libsmeac.lib
OBJECTS2 = sm-eac.obj

TARGET3 = libsmnist.lib
OBJECTS3 = sm-nist.obj

all: $(TARGET) $(TARGET1) $(TARGET2) $(TARGET3)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"

$(TARGET): $(OBJECTS)
        lib $(LIBFLAGS) /out:$(TARGET) $(OBJECTS)

!ELSE
$(TARGET):

!ENDIF

$(TARGET1): $(OBJECTS1)
        lib $(LIBFLAGS) /out:$(TARGET1) $(OBJECTS1)

$(TARGET2): $(OBJECTS2)
        lib $(LIBFLAGS) /out:$(TARGET2) $(OBJECTS2)

$(TARGET3): $(OBJECTS3)
        lib $(LIBFLAGS) /out:$(TARGET3) $(OBJECTS3)

