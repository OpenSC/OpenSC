all: opensc.conf

opensc.conf: opensc.conf.in
	@copy /y opensc.conf.in opensc.conf

clean::
	del /Q opensc.conf

