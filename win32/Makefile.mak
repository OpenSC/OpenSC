
all: config.h

config.h: winconfig.h
	@copy /y winconfig.h config.h

clean::
	del /Q config.h

