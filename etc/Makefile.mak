all: opensc.conf.win

opensc.conf.win: opensc.conf.in
	@IF DEFINED USE_SED (sed.exe s/@DEBUG_FILE@/\%TEMP\%\\opensc-debug.log/;s/@DEFAULT_SM_MODULE@/smm-local.dll/ opensc.conf.in > opensc.conf.win) ELSE (copy /y opensc.conf.in opensc.conf.win)

clean::
	del /Q opensc.conf.win

