#include <opensc.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	int i, len;
	FILE *inf;
	char buf[8192];

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
	sc_asn1_print_tags(buf, len);
	return 0;
}
