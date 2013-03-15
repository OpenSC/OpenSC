all: opensc.conf.win

opensc.conf.win: opensc.conf.win.in
	copy /y opensc.conf.win.in opensc.conf.win

clean::
	del /Q opensc.conf.win

