#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#ifndef _WIN32
#include <termios.h>
#else
#include <conio.h>
#endif
#include <ctype.h>
#include "util.h"

int util_connect_card(sc_context_t *ctx, sc_card_t **cardp,
		 const char *reader_id, int do_wait, int verbose)
{
	sc_reader_t *reader, *found;
	sc_card_t *card;
	int r, tmp_reader_num;

	if (do_wait) {
		unsigned int event;

		if (sc_ctx_get_reader_count(ctx) == 0) {
			fprintf(stderr, "Waiting for a reader to be attached...\n");
			r = sc_wait_for_event(ctx, SC_EVENT_READER_ATTACHED, &found, &event, -1, NULL);
			if (r < 0) {
				fprintf(stderr, "Error while waiting for a reader: %s\n", sc_strerror(r));
				return 3;
			}
			r = sc_ctx_detect_readers(ctx);
			if (r < 0) {
				fprintf(stderr, "Error while refreshing readers: %s\n", sc_strerror(r));
				return 3;
			}
		}
		fprintf(stderr, "Waiting for a card to be inserted...\n");
		r = sc_wait_for_event(ctx, SC_EVENT_CARD_INSERTED, &found, &event, -1, NULL);
		if (r < 0) {
			fprintf(stderr, "Error while waiting for a card: %s\n", sc_strerror(r));
			return 3;
		}
		reader = found;
	} else {
		if (sc_ctx_get_reader_count(ctx) == 0) {
			fprintf(stderr,
				"No smart card readers found.\n");
			return 1;
		}
		if (!reader_id) {
			unsigned int i;
			/* Automatically try to skip to a reader with a card if reader not specified */
			for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
				reader = sc_ctx_get_reader(ctx, i);
				if (sc_detect_card_presence(reader) & SC_READER_CARD_PRESENT) {
					fprintf(stderr, "Using reader with a card: %s\n", reader->name);
					goto autofound;
				}
			}
			/* If no reader had a card, default to the first reader */
			reader = sc_ctx_get_reader(ctx, 0);
		} else {
			/* If the reader identifiers looks like an ATR, try to find the reader with that card */
			unsigned char atr_buf[SC_MAX_ATR_SIZE * 3];
			size_t atr_buf_len = sizeof(atr_buf);
			unsigned int i;
			if (sc_hex_to_bin(reader_id, atr_buf, &atr_buf_len) == SC_SUCCESS) {
				/* Loop readers, looking for a card with ATR */
				for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
					reader = sc_ctx_get_reader(ctx, i);
					if (sc_detect_card_presence(reader) & SC_READER_CARD_PRESENT) {
						if (!memcmp(reader->atr, atr_buf, reader->atr_len)) {
							fprintf(stderr, "Matched ATR in reader: %s\n", reader->name);
							goto autofound;
						}	
					}
				}		
			}
			if (!sscanf(reader_id, "%d", &tmp_reader_num)) {
				/* Try to get the reader by name if it does not parse as a number */
				reader = sc_ctx_get_reader_by_name(ctx, reader_id);
			} else {
				reader = sc_ctx_get_reader(ctx, tmp_reader_num);
			}
		}
autofound:
		if (!reader) {
			fprintf(stderr,
				"Reader \"%s\" not found (%d reader(s) detected)\n", reader_id, sc_ctx_get_reader_count(ctx));
			return 1;
		}

		if (sc_detect_card_presence(reader) <= 0) {
			fprintf(stderr, "Card not present.\n");
			return 3;
		}
	}

	if (verbose)
		printf("Connecting to card in reader %s...\n", reader->name);
	if ((r = sc_connect_card(reader, &card)) < 0) {
		fprintf(stderr,
			"Failed to connect to card: %s\n",
			sc_strerror(r));
		return 1;
	}

	if (verbose)
		printf("Using card driver %s.\n", card->driver->name);

	if ((r = sc_lock(card)) < 0) {
		fprintf(stderr,
			"Failed to lock card: %s\n",
			sc_strerror(r));
		sc_disconnect_card(card);
		return 1;
	}

	*cardp = card;
	return 0;
}

void util_print_binary(FILE *f, const u8 *buf, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		unsigned char c = buf[i];
		const char *format;
		if (!isprint(c))
			format = "\\x%02X";
		else
			format = "%c";
		fprintf(f, format, c);
	}
	(void) fflush(f);
}

void util_hex_dump(FILE *f, const u8 *in, int len, const char *sep)
{
	int i;

	for (i = 0; i < len; i++) {
		if (sep != NULL && i)
			fprintf(f, "%s", sep);
		fprintf(f, "%02X", in[i]);
	}
}

void util_hex_dump_asc(FILE *f, const u8 *in, size_t count, int addr)
{
	int lines = 0;

 	while (count) {
		char ascbuf[17];
		size_t i;

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

void util_print_usage_and_die(const char *app_name, const struct option options[],
	const char *option_help[])
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

const char * util_acl_to_str(const sc_acl_entry_t *e)
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
util_fatal(const char *fmt, ...)
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
util_error(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	fprintf(stderr, "error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

void
util_warn(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	fprintf(stderr, "warning: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

int
util_getpass (char **lineptr, size_t *len, FILE *stream)
{
#define MAX_PASS_SIZE	128
	char *buf;
	unsigned int i;
#ifndef _WIN32
	struct termios old, new;

	fflush(stdout);
	if (tcgetattr (fileno (stdout), &old) != 0)
		return -1;
	new = old;
	new.c_lflag &= ~ECHO;
	if (tcsetattr (fileno (stdout), TCSAFLUSH, &new) != 0)
		return -1;
#endif

	buf = calloc(1, MAX_PASS_SIZE);
	if (!buf)
		return -1;

	for (i = 0; i < MAX_PASS_SIZE - 1; i++) {
#ifndef _WIN32
		buf[i] = getchar();
#else
		buf[i] = _getch();
#endif
		if (buf[i] == 0 || buf[i] == 3)
			break;
		if (buf[i] == '\n' || buf[i] == '\r')
			break;
	}
#ifndef _WIN32
	tcsetattr (fileno (stdout), TCSAFLUSH, &old);
	fputs("\n", stdout);
#endif
	if (buf[i] == 0 || buf[i] == 3) {
		free(buf);
		return -1;
	}

	buf[i] = 0;

	if (*lineptr && (!len || *len < i+1)) {
		free(*lineptr);
		*lineptr = NULL;
	}

	if (*lineptr) {
		memcpy(*lineptr,buf,i+1);
		memset(buf, 0, MAX_PASS_SIZE);
		free(buf);
	} else {
		*lineptr = buf;
		if (len)
			*len = MAX_PASS_SIZE;
	}
	return i;
}

