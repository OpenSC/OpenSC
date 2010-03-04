#include "config.h"

#include <stdio.h>

#include "libopensc/opensc.h"
#include "libopensc/asn1.h"

int main(int argc, char *argv[])
{
	int len;
	FILE *inf;
	u8 buf[8192];
	u8 outbuf[8192];

	if (argc != 2) {
		fprintf(stderr, "Usage: base64 <file>\n");
		return 1;
	}
	inf = fopen(argv[1], "r");
	if (inf == NULL) {
		perror(argv[1]);
		return 1;
	}
	len = fread(buf, 1, sizeof(buf), inf);
	if (len < 0) {
		perror("fread");
		return 1;
	}
	if (len == 8192) {
		fprintf(stderr, "Too long input file.\n");
		return 1;
	}
	len = sc_base64_decode((const char *) buf, outbuf, sizeof(outbuf));
	if (len < 0) {
		fprintf(stderr, "Base64 decoding failed: %s\n", sc_strerror(len));	
		return 1;
	}
	fwrite(outbuf, len, 1, stdout);
	return 0;
}
