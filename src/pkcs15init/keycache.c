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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <assert.h>
#include <opensc/pkcs15.h>
#include <opensc/cardctl.h>
#include "profile.h"
#include "pkcs15-init.h"

#undef KEYCACHE_DEBUG
#define MAX_SECRET	32	/* sufficient for 128bit symmetric keys */

struct secret {
	struct secret *	next;
	sc_path_t	path;
	int		type, ref, named_pin;
	size_t		len;
	unsigned char	value[MAX_SECRET];
};

static struct secret *	secret_cache = NULL;
static struct secret *	named_pin[SC_PKCS15INIT_NPINS];

#ifdef KEYCACHE_DEBUG
static void		sc_keycache_dump(void);
#endif

/*
 * Check if a keycache entry matches the given type, reference
 * and path.
 */
static int
__match_entry(struct secret *s, int type, int ref, const sc_path_t *path,
		int match_prefix)
{
	if ((type != -1 && s->type != type)
	 || (ref  != -1 && s->ref  != ref))
		return 0;

	/* Compare the two paths */
	if (match_prefix) {
		/* Prefix match - the path argument given by
		 * the caller should be a prefix of the keycache
		 * entry.
		 */
		/* If the path is a wildcard, it's a match */
		if (path == NULL)
			return 1;
		if (s->path.len > path->len)
			return 0;
	} else {
		/* Exact match - path names must patch exactly.
		 * A NULL path argument is an empty path */
		if (path == 0)
			return (s->path.len == 0);
		if (s->path.len != path->len)
			return 0;
	}
	if (memcmp(s->path.value, path->value, s->path.len))
		return 0;

	return 1;
}

/*
 * Find the secret, given a path name, type and reference.
 * If none found, search for it in parent directories.
 */
static struct secret *
find_entry(const sc_path_t *path, int type, int ref, int match_prefix)
{
	struct secret	*s;

	if (type == SC_AC_SYMBOLIC) {
		if (0 <= ref && ref < SC_PKCS15INIT_NPINS
		 && (s = named_pin[ref]) != NULL
		 && __match_entry(s, SC_AC_CHV, -1, path, match_prefix))
			return s;
		return NULL;
	}

	for (s = secret_cache; s; s = s->next) {
		if (__match_entry(s, type, ref, path, match_prefix))
			break;
	}

	return s;
}

/*
 * Find a key with matching type/reference. If a path is
 * given, find the entry with the longest matching prefix.
 */
static struct secret *
search_key(const sc_path_t *path, int type, int ref)
{
	struct secret	*best = NULL, *s;

	if (type == SC_AC_SYMBOLIC) {
		if (0 <= ref && ref < SC_PKCS15INIT_NPINS
		 && (s = named_pin[ref]) != NULL
		 && __match_entry(s, type, -1, path, 1))
			return s;
		return NULL;
	}

	for (s = secret_cache; s; s = s->next) {
		if (s->len != 0
		 && __match_entry(s, type, ref, path, 1)) {
			/* Ignore if path shorter than the longest
			 * matched prefix.
			 */
			if (path == NULL || best == NULL
			 || best->path.len < path->len)
				best = s;
		}
	}

	return best;
}

/*
 * Store a secret in the cache
 */
static struct secret *
new_entry(const sc_path_t *path, int type, int ref)
{
	struct secret	*s;

	s = (struct secret *) calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;
	s->next = secret_cache;
	secret_cache = s;
	if (path)
		s->path = *path;
	if (type == SC_AC_SYMBOLIC) {
		s->type = SC_AC_CHV;
		s->ref = -1;
		s->named_pin = ref;
	} else {
		s->type = type;
		s->ref = ref;
		s->named_pin = -1;
	}
	return s;
}

/*
 * Cache the given key
 */
int
sc_keycache_put_key(const sc_path_t *path, int type, int ref,
			const unsigned char *secret, size_t len)
{
	struct secret	*s;

	if (len > MAX_SECRET)
		return SC_ERROR_BUFFER_TOO_SMALL;

	if (!(s = find_entry(path, type, ref, 0))) {
		s = new_entry(path, type, ref);
		if (s == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		if (type == SC_AC_SYMBOLIC)
			named_pin[ref] = s;
	}

	memset(s->value, 0, sizeof(s->value));
	memcpy(s->value, secret, len);
	s->len = len;

#ifdef KEYCACHE_DEBUG
	sc_keycache_dump();
#endif
	return 0;
}

int
sc_keycache_put_pin(const sc_path_t *path, int ref, const u8 *pin)
{
	return sc_keycache_put_key(path, SC_AC_CHV, ref, pin,
					pin? strlen((const char *) pin) : 0);
}

/*
 * Get a key/pin from the cache
 */
int
sc_keycache_get_key(const sc_path_t *path, int type, int ref,
			unsigned char *key, size_t size)
{
	struct secret	*s;

	if (!(s = search_key(path, type, ref)))
		return SC_ERROR_OBJECT_NOT_FOUND;

	if (s->len > size)
		return SC_ERROR_BUFFER_TOO_SMALL;
	memcpy(key, s->value, s->len);
	return s->len;
}

const u8 *
sc_keycache_get_pin(const sc_path_t *path, int ref)
{
	struct secret	*s;

	if (!(s = search_key(path, SC_AC_CHV, ref)))
		return NULL;

	return s->len? s->value : NULL;
}

/*
 * Define a symbolic name for a PIN. This is used to define
 * what $PIN and $SOPIN mean in a given context.
 */
int
sc_keycache_set_pin_name(const sc_path_t *path, int ref, int name)
{
	struct secret	*s, *old;

	if (name < 0 || name >= SC_PKCS15INIT_NPINS)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* If we had previously marked a PIN with this name,
	 * unlink it */
	if ((old = named_pin[name]) != NULL) {
		named_pin[name] = NULL;
		old->named_pin = -1;
	}

	if (ref >= 0) {
		/* Create the named PIN if it doesn't exist */
		if (!(s = find_entry(path, SC_AC_CHV, ref, 0))) {
			s = new_entry(path, SC_AC_CHV, ref);
			if (s == NULL)
				return SC_ERROR_OUT_OF_MEMORY;
		}

		/* Set the pin name */
		s->named_pin = name;

		/* If the old SOPIN was just the name entry,
		 * copy over the name to the new entry */
		if (old && old->ref == -1 && s->len == 0) {
			memcpy(s->value, old->value, old->len);
			s->len = old->len;
		}

		named_pin[name] = s;
	}

#ifdef KEYCACHE_DEBUG
	sc_keycache_dump();
#endif
	return 0;
}

/*
 * Get the symbolic name of a PIN, if any
 */
int
sc_keycache_get_pin_name(const sc_path_t *path, int ref)
{
	struct secret	*s;

#ifdef KEYCACHE_DEBUG
	printf("sc_keycache_get_pin_name(%s, %d)\n",
			path? sc_print_path(path) : "any", ref);
#endif

	if (!(s = find_entry(path, SC_AC_CHV, ref, 1)))
		return -1;
	return s->named_pin;
}

/*
 * Get path and reference of symbolic PIN
 */
int
sc_keycache_find_named_pin(const sc_path_t *path, int name)
{
	struct secret	*s;

	if (name < 0 || name >= SC_PKCS15INIT_NPINS
	 || (s = named_pin[name]) == NULL
	 || !__match_entry(s, SC_AC_CHV, -1, path, 1))
		return -1;

	return s->ref;
}

/*
 * Zap one or more keys from the cache
 */
void
sc_keycache_forget_key(const sc_path_t *path, int type, int ref)
{
	struct secret	*s, **prev;

	prev = &secret_cache;
	while ((s = *prev) != NULL) {
		if (__match_entry(s, type, ref, path, 1)) {
			*prev = s->next;
			if (s->named_pin >= 0 && s->named_pin < SC_PKCS15INIT_NPINS)
				named_pin[s->named_pin] = NULL;
			sc_mem_clear(s, sizeof(*s));
			free(s);
		} else {
			prev = &s->next;
		}
	}
#ifdef KEYCACHE_DEBUG
	sc_keycache_dump();
#endif
}

/*
 * Dump the keycache
 */
#ifdef KEYCACHE_DEBUG
void
sc_keycache_dump(void)
{
	struct secret	*s;
	int		j;

	printf("== Keycache ==\n");
	for (s = secret_cache; s; s = s->next) {
		char	buf[32];

		switch (s->type) {
		case SC_AC_CHV: printf("CHV"); break;
		case SC_AC_AUT: printf("AUT"); break;
		case SC_AC_PRO: printf("PRO"); break;
		default:	printf("%d/", s->type);
		}
		printf("%d %-16s\t", s->ref, sc_print_path(&s->path));
		sc_bin_to_hex(s->value, s->len, buf, sizeof(buf), ':');
		printf("key=%s", buf);

		switch (s->named_pin) {
		case SC_PKCS15INIT_SO_PIN:
			printf(", SO PIN"); break;
		case SC_PKCS15INIT_SO_PUK:
			printf(", SO PUK"); break;
		case SC_PKCS15INIT_USER_PIN:
			printf(", USER PIN"); break;
		case SC_PKCS15INIT_USER_PUK:
			printf(", USER PUK"); break;
		}

		if (s->named_pin >= 0
		 && named_pin[s->named_pin] != s)
			printf(" [PTR MISMATCH!]");
		printf("\n");
	}

	for (j = 0; j < SC_PKCS15INIT_NPINS; j++) {
		if ((s = named_pin[j]) == NULL)
			continue;
		if (s->named_pin != j)
			printf(" named_pin[%d] MISMATCH: name=%d\n",
					j, s->named_pin);
	}
}
#endif
