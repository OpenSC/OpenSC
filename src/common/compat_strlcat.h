/**
 * @file
 * @brief prototypes of strlcpy()/strlcat() imported from OpenBSD
 */

#ifndef HAVE_STRLCAT
#include <stddef.h>
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
