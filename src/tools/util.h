#ifndef UTIL_H
#define UTIL_H

#include "config.h"

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

#include <getopt.h>
#include "libopensc/opensc.h"

#ifdef __cplusplus
extern "C" {
#endif

#if _MSC_VER >= 1310
/* MS Visual Studio 2003/.NET Framework 1.1 or newer */
# define NORETURN _declspec( noreturn)
#elif __GNUC__ > 2 || (__GNUC__ == 2 && (__GNUC_MINOR__ >= 5)) || (defined __clang__)
# define NORETURN __attribute__ ((noreturn))
#elif __cplusplus >= 201103L
# define NORETURN [[noreturn]]
#elif __STDC_VERSION__ >= 201112L
# define NORETURN _Noreturn
#else
# define NORETURN
#endif

void util_print_binary(FILE *f, const u8 *buf, int count);
void util_hex_dump(FILE *f, const u8 *in, int len, const char *sep);
void util_hex_dump_asc(FILE *f, const u8 *in, size_t count, int addr);
NORETURN void util_print_usage_and_die(const char *app_name, const struct option options[],
	const char *option_help[], const char *args);
int util_list_card_drivers(const sc_context_t *ctx);
const char * util_acl_to_str(const struct sc_acl_entry *e);
void util_warn(const char *fmt, ...);
void util_error(const char *fmt, ...);
NORETURN void util_fatal(const char *fmt, ...);

int util_connect_reader (sc_context_t *ctx, sc_reader_t **reader, const char *reader_id, int do_wait, int verbose);
/* All singing all dancing card connect routine */
int util_connect_card_ex(struct sc_context *, struct sc_card **, const char *reader_id, int do_wait, int do_lock, int verbose);
int util_connect_card(struct sc_context *, struct sc_card **, const char *reader_id, int do_wait, int verbose);

int util_getpass (char **lineptr, size_t *n, FILE *stream);

/* Get a PIN (technically just a string). The source depends on the value of *input:
 * env:<var> - get from the environment variable <var>
 * otherwise - use input
 */
size_t util_get_pin(const char *input, const char **pin);

#ifdef __cplusplus
}
#endif

#endif
