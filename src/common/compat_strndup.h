/**
 * @file
 * @brief prototype of strndup()
 */

#ifndef __COMPAT_STRNDUP_H
#define __COMPAT_STRNDUP_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_STRNDUP
#include <stddef.h>
/* Workaround for mingw gcc nonnull-compare error */
#define strndup _strndup
char *_strndup(const char *str, size_t n);
#else
#include <string.h>
#endif

#endif
