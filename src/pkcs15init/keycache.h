/*
 * Cache authentication info
 *
 * Copyright (C) 2003, Olaf Kirch <okir@lst.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _PKCS15INIT_KEYCACHE_H
#define _PKCS15INIT_KEYCACHE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <opensc/opensc.h>

extern int	sc_keycache_put_key(const sc_path_t *, int, int,
				const unsigned char *, size_t);
extern int	sc_keycache_put_pin(const sc_path_t *, int, const u8 *);
extern int	sc_keycache_set_pin_name(const sc_path_t *, int, int);
extern int	sc_keycache_get_pin_name(const sc_path_t *, int);
extern int	sc_keycache_find_named_pin(const sc_path_t *, int);
extern int	sc_keycache_get_key(const sc_path_t *, int, int, unsigned char *, size_t);
extern const u8 *sc_keycache_get_pin(const sc_path_t *, int);
extern void	sc_keycache_forget_key(const sc_path_t *, int, int);

#ifdef __cplusplus
}
#endif

#endif /* _PKCS15INIT_KEYCACHE_H */
