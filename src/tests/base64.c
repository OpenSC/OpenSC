#include "config.h"

#include <stdio.h>

#include "libopensc/opensc.h"
#include "libopensc/asn1.h"

#ifdef _MSC_VER
# ifndef _SSIZE_T_DEFINED
#  undef ssize_t
#  include <BaseTsd.h>
   typedef _W64 SSIZE_T ssize_t;
#  define _SSIZE_T_DEFINED
# endif /* _SSIZE_T_DEFINED */
#endif /* _MSC_VER */


int main(int argc, char *argv[])
{
	int len, r = 1;
	FILE *inf = NULL;
	u8 buf[8192];
	u8 outbuf[8192];
	ssize_t sz;

	if (argc != 2) {
		fprintf(stderr, "Usage: base64 <file>\n");
		goto err;
	}
	inf = fopen(argv[1], "r");
	if (inf == NULL) {
		perror(argv[1]);
		goto err;
	}
	sz = fread(buf, 1, sizeof(buf), inf);
	if (sz < 0) {
		perror("fread");
		goto err;
	}
	if (sz == 8192) {
		fprintf(stderr, "Too long input file.\n");
		goto err;
	}
	len = sc_base64_decode((const char *) buf, outbuf, sizeof(outbuf));
	if (len < 0) {
		fprintf(stderr, "Base64 decoding failed: %s\n", sc_strerror(len));
		goto err;
	}
	fwrite(outbuf, len, 1, stdout);
	r = 0;
err:
	if (inf)
		fclose(inf);
	return r;
}
