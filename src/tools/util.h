

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <opensc.h>

void print_binary(FILE *f, const u8 *buf, int count);
void hex_dump(FILE *f, const u8 *in, int len);
void hex_dump_asc(FILE *f, const u8 *in, size_t count);

#endif
