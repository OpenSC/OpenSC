

#ifndef UTIL_H
#define UTIL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <opensc.h>

extern const struct option options[];
extern const char *option_help[];

void print_binary(FILE *f, const u8 *buf, int count);
void hex_dump(FILE *f, const u8 *in, int len);
void hex_dump_asc(FILE *f, const u8 *in, size_t count);
void print_usage_and_die(const char *pgmname);

#endif
