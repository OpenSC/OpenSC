How to compile src\tools\pkcs15-init.c:

- download and compile the openssl sources from
  http://www.openssl.org/source/

- Add the inc32\ dir to your include path,
      the out32dll\ to your lib path and your executable path
  set include=%include%;.....\inc32
  set lib=%lib%;.....\out32dll
  set path=%path%;....\out32dll

- In src/tools/Makefile.mak
  - uncomment pkcs15-init.exe in the "TARGETS" line
  - Add libeay32.lib to the "link" line


