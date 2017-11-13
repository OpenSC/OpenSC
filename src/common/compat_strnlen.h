/**
 * @file
 * @brief prototype of strnlen() from OpenBSD
 */

#ifndef HAVE_STRNLEN
#include <stddef.h>
size_t strnlen(const char *str, size_t maxlen);
#endif
