#ifndef UTIL_H
#define UTIL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <compat_getopt.h>
#include <opensc/opensc.h>

#ifdef __cplusplus
extern "C" {
#endif

void util_print_binary(FILE *f, const u8 *buf, int count);
void util_hex_dump(FILE *f, const u8 *in, int len, const char *sep);
void util_hex_dump_asc(FILE *f, const u8 *in, size_t count, int addr);
void util_print_usage_and_die(const char *app_name, const struct option options[],
	const char *option_help[]);
const char * util_acl_to_str(const struct sc_acl_entry *e);
void util_warn(const char *fmt, ...);
void util_error(const char *fmt, ...);
void util_fatal(const char *fmt, ...);
/* All singing all dancing card connect routine */
int util_connect_card(struct sc_context *, struct sc_card **,
		int reader_id, int slot_id, int wait, int verbose);

#ifdef __cplusplus
}
#endif

#endif
