TOPDIR = ..

TARGET			= version.res

VERSION_RC		= version.rc

RSC_PROJ=/l 0x809 /r /fo"version.res"

all: $(TARGET)

$(TARGET): $(VERSION_RC)
	rc $(RSC_PROJ) $(VERSION_RC)
