#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include "util.h"

int connect_card(struct sc_context *ctx, struct sc_card **cardp,
		 int reader_id, int slot_id, int wait, int quiet)
{
	struct sc_reader *reader;
	int r;

	if (wait) {
		struct sc_reader *readers[16];
		int slots[16];
		int i, j, k, found;
		unsigned int event;

		for (i = k = 0; i < ctx->reader_count; i++) {
			if (reader_id >= 0 && reader_id != i)
				continue;
			reader = ctx->reader[i];
			for (j = 0; j < reader->slot_count; j++, k++) {
				readers[k] = reader;
				slots[k] = j;
			}
		}

		printf("Waiting for card to be inserted...\n");
		r = sc_wait_for_event(readers, slots, k,
				SC_EVENT_CARD_INSERTED,
				&found, &event, -1);
		if (r < 0) {
			fprintf(stderr,
				"Error while waiting for card: %s\n",
				sc_strerror(r));
			return 3;
		}

		reader = readers[found];
		slot_id = slots[found];
	} else {
		if (reader_id < 0)
			reader_id = 0;
		if (ctx->reader_count == 0) {
			fprintf(stderr,
				"No smart card readers configured.\n");
			return 1;
		}
		if (reader_id >= ctx->reader_count) {
			fprintf(stderr,
				"Illegal reader number. "
				"Only %d reader(s) configured.\n",
				ctx->reader_count);
			return 1;
		}

		reader = ctx->reader[reader_id];
		slot_id = 0;
		if (sc_detect_card_presence(reader, 0) <= 0) {
			fprintf(stderr, "Card not present.\n");
			return 3;
		}
	}

	if (!quiet) {
		fprintf(stderr, "Connecting to card in reader %s...\n",
			reader->name);
	}
	if ((r = sc_connect_card(reader, slot_id, cardp)) < 0) {
		fprintf(stderr,
			"Failed to connect to card: %s\n",
			sc_strerror(r));
		return 1;
	}

	return 0;
}

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

void print_usage_and_die(void)
{
	int i = 0;
	printf("Usage: %s [OPTIONS]\nOptions:\n", app_name);

	while (options[i].name) {
		char buf[40], tmp[5];
		const char *arg_str;
		
		/* Skip "hidden" options */
		if (option_help[i] == NULL) {
			i++;
			continue;
		}

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
		if (strlen(buf) > 29) {
			printf("  %s\n", buf);
			buf[0] = '\0';
		}
		printf("  %-29s %s\n", buf, option_help[i]);
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

void
fatal(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	fprintf(stderr, "error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\nAborting.\n");
	va_end(ap);
	exit(1);
}

void
error(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	fprintf(stderr, "error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

void
warn(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	fprintf(stderr, "warning: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}
