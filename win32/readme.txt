How to add openssl for extended functionality
(e.g. hash mechanisms, the pkcs15-init tool, more signature
mechanism)

- download and compile the openssl sources from
  http://www.openssl.org/source/

- Add the inc32\ dir to your include path,
      the out32dll\ to your lib path and your executable path
  set include=%include%;.....\inc32
  set lib=%lib%;.....\out32dll
  set path=%path%;....\out32dll

- In src/tools/Makefile.mak
  - uncomment pkcs15-init.exe in the "TARGETS" line  (optionally)
  - Add libeay32.lib to the "link" line

- In src/libopensc/Makefile.mak
  - Add libeay32.lib to the "link" line

- In src/pkcs11/Makefile.mak
  - Add libeay32.lib to the "link" line

- In win32/Make.rules.mak
  - Add /DHAVE_OPENSSL to the "COPTS" line


To add the OpenSSL code to the DLLs (so you won't need libeay32.dll
anymore): statically compile OpenSSL and add gdi32.lib next to
libeay32.lib in the 3 Makefile.mak files above.
