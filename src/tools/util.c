#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "util.h"

void print_binary(FILE *f, const u8 *buf, int count)
{
	int i;
	
	for (i = 0; i < count; i++) {
		unsigned char c = buf[i];
		const char *format;
		if (!isalnum(c) && !ispunct(c) && !isspace(c))
			format = "\\x%02X";
		else
			format = "%c";
		fprintf(f, format, c);
	}
	(void) fflush(f);
}

void hex_dump(FILE *f, const u8 *in, int len, const char *sep)
{
	int i;
	
	for (i = 0; i < len; i++) {
		if (sep != NULL && i)
			fprintf(f, "%s", sep);
		fprintf(f, "%02X", in[i]);
	}
}

void hex_dump_asc(FILE *f, const u8 *in, size_t count, int addr)
{
	int lines = 0;

 	while (count) {
		char ascbuf[17];
		int i;
		
		if (addr >= 0) {
			fprintf(f, "%08X: ", addr);
			addr += 16;
		}
		for (i = 0; i < count && i < 16; i++) {
			fprintf(f, "%02X ", *in);
			if (isprint(*in))
				ascbuf[i] = *in;
			else
				ascbuf[i] = '.';
			in++;
		}
		count -= i;
		ascbuf[i] = 0;
		for (; i < 16 && lines; i++)
			fprintf(f, "   ");
		fprintf(f, "%s\n", ascbuf);
		lines++;
	}
}

void print_usage_and_die(const char *pgmname)
{
	int i = 0;
	printf("Usage: %s [OPTIONS]\nOptions:\n", pgmname);

	while (options[i].name) {
		char buf[40], tmp[5];
		const char *arg_str;
		
		if (options[i].val > 0 && options[i].val < 128)
			sprintf(tmp, ", -%c", options[i].val);
		else
			tmp[0] = 0;
		switch (options[i].has_arg) {
		case 1:
			arg_str = " <arg>";
			break;
		case 2:
			arg_str = " [arg]";
			break;
		default:
			arg_str = "";
			break;
		}
		sprintf(buf, "--%s%s%s", options[i].name, tmp, arg_str);
		printf("  %-30s%s\n", buf, option_help[i]);
		i++;
	}
	exit(2);
}

const char * acl_to_str(const struct sc_acl_entry *e)
{
	static char line[80], buf[10];
	unsigned int acl;
	
	if (e == NULL)
		return "N/A";
	line[0] = 0;
	while (e != NULL) {
		acl = e->method;

		switch (acl) {
		case SC_AC_UNKNOWN:
			return "N/A";
		case SC_AC_NEVER:
			return "NEVR";
		case SC_AC_NONE:
			return "NONE";
		case SC_AC_CHV:
			strcpy(buf, "CHV");
			if (e->key_ref != SC_AC_KEY_REF_NONE)
				sprintf(buf + 3, "%d", e->key_ref);
			break;
		case SC_AC_TERM:
			strcpy(buf, "TERM");
			break;
		case SC_AC_PRO:
			strcpy(buf, "PROT");
			break;
		case SC_AC_AUT:
			strcpy(buf, "AUTH");
			if (e->key_ref != SC_AC_KEY_REF_NONE)
				sprintf(buf + 4, "%d", e->key_ref);
			break;
		default:
			strcpy(buf, "????");
			break;
		}
		strcat(line, buf);
		strcat(line, " ");
		e = e->next;
	}
	line[strlen(line)-1] = 0; /* get rid of trailing space */
	return line;
}
