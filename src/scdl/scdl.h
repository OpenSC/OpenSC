/*
 * Dynamic loading routines for various platforms, to
 * be used internally in several places.
 *
 * No interface for portable error handling, maybe
 * later.
 *
 * Copyright (C) 2003  Antti Tapaninen <aet@cc.hut.fi>
 *                     Olaf Kirch <okir@lst.de>
 *                     Stef Hoeben <stef.hoeben@zetes.com>
 */

#ifndef _SC_DL_H
#define _SC_DL_H

#ifdef __cplusplus
extern "C" {
#endif

extern void *scdl_open(const char *name);
extern int scdl_close(void *module);
extern void *scdl_get_address(void *module, const char *symbol);

#ifdef __cplusplus
}
#endif
#endif
