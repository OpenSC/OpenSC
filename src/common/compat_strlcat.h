/**
 * @file
 * @brief prototypes of strlcat() imported from OpenBSD
 */

#ifndef __COMPAT_STRLCAT_H
#define __COMPAT_STRLCAT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_STRLCAT
#include <stddef.h>
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#endif
