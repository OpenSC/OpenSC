/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2004
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id: strlcpycat.h 1421 2005-04-12 12:09:21Z rousseau $
 */

/**
 * @file
 * @brief prototypes of strlcpy()/strlcat() imported from OpenBSD
 */

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif
