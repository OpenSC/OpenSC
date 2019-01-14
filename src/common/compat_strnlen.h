/**
 * @file
 * @brief prototype of strnlen() from OpenBSD
 */

#ifndef __COMPAT_STRNLEN_H
#define __COMPAT_STRNLEN_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_STRNLEN
#include <stddef.h>
size_t strnlen(const char *str, size_t maxlen);
#endif

#endif
