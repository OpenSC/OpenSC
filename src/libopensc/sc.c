/*
 * sc.c: General functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "internal.h"
#include "asn1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef VERSION
const char *sc_version = VERSION;
#else
const char *sc_version = "(undef)";
#endif

const char *sc_get_version(void)
{
    return sc_version;
}

int sc_hex_to_bin(const char *in, u8 *out, size_t *outlen)
{
	int err = 0;
	size_t left, count = 0;

	assert(in != NULL && out != NULL && outlen != NULL);
        left = *outlen;

	while (*in != '\0') {
		int byte = 0, nybbles = 2;
		char c;

		while (nybbles-- && *in && *in != ':') {
			byte <<= 4;
			c = *in++;
			if ('0' <= c && c <= '9')
				c -= '0';
			else
			if ('a' <= c && c <= 'f')
				c = c - 'a' + 10;
			else
			if ('A' <= c && c <= 'F')
				c = c - 'A' + 10;
			else {
				err = SC_ERROR_INVALID_ARGUMENTS;
				goto out;
			}
			byte |= c;
		}
		if (*in == ':')
			in++;
		if (left <= 0) {
                        err = SC_ERROR_BUFFER_TOO_SMALL;
			break;
		}
		out[count++] = (u8) byte;
		left--;
		c++;
	}

out:
	*outlen = count;
	return err;
}

int sc_bin_to_hex(const u8 *in, size_t in_len, char *out, size_t out_len,
		  char sep)
{
	unsigned int	n, sep_len;
	char		*pos, *end;

	sep_len = sep > 0 ? 1 : 0;
	pos = out;
	end = out + out_len;
	for (n = 0; n < in_len; n++) {
		if (pos + 3 + sep_len >= end)
			return SC_ERROR_BUFFER_TOO_SMALL;
		if (n && sep_len)
			*pos++ = sep;
		sprintf(pos, "%02x", in[n]);
		pos += 2;
	}
	*pos = '\0';
	return 0;
}

struct sc_slot_info * _sc_get_slot_info(struct sc_reader *reader, int slot_id)
{
	assert(reader != NULL);
	if (slot_id < 0 || slot_id > reader->slot_count)
		return NULL;
	return &reader->slot[slot_id];
}

int sc_detect_card_presence(struct sc_reader *reader, int slot_id)
{
	int r;
	struct sc_slot_info *slot = _sc_get_slot_info(reader, slot_id);
	
	if (slot == NULL)
		SC_FUNC_RETURN(reader->ctx, 0, SC_ERROR_SLOT_NOT_FOUND);
	SC_FUNC_CALLED(reader->ctx, 1);
	if (reader->ops->detect_card_presence == NULL)
		SC_FUNC_RETURN(reader->ctx, 0, SC_ERROR_NOT_SUPPORTED);
	
	r = reader->ops->detect_card_presence(reader, slot);
	SC_FUNC_RETURN(reader->ctx, 1, r);
}

int sc_wait_for_event(struct sc_reader *readers[], int slot_id[], size_t nslots,
                      unsigned int event_mask,
                      int *reader, unsigned int *event, int timeout)
{
	struct sc_slot_info *slotp[SC_MAX_SLOTS * SC_MAX_READERS];
	struct sc_context *ctx;
	unsigned int j;
	int r;

	if (nslots == 0 || nslots > SC_MAX_SLOTS * SC_MAX_READERS)
	       return SC_ERROR_INVALID_ARGUMENTS;
	ctx = readers[0]->ctx;

	SC_FUNC_CALLED(ctx, 1);
	for (j = 0; j < nslots; j++) {
		slotp[j] = _sc_get_slot_info(readers[j], slot_id[j]);

		if (slotp[j] == NULL)
			SC_FUNC_RETURN(ctx, 0, SC_ERROR_SLOT_NOT_FOUND);
		/* XXX check to make sure all readers share the same operations
		 * struct */
	}

	if (readers[0]->ops->wait_for_event == NULL)
	       SC_FUNC_RETURN(ctx, 0, SC_ERROR_NOT_SUPPORTED);

	r = readers[0]->ops->wait_for_event(readers, slotp, nslots,
				       event_mask, reader, event, timeout);
	SC_FUNC_RETURN(ctx, 1, r);
}

void sc_format_path(const char *str, struct sc_path *path)
{
	int type = SC_PATH_TYPE_PATH;

	memset(path, 0, sizeof(*path));
	if (*str == 'i' || *str == 'I') {
		type = SC_PATH_TYPE_FILE_ID;
		str++;
	}
	path->len = sizeof(path->value);
	if (sc_hex_to_bin(str, path->value, &path->len) >= 0) {
		path->type = type;
	}
	return;
}

int sc_append_path(struct sc_path *dest, const struct sc_path *src)
{
	assert(dest != NULL && src != NULL);
	if (dest->len + src->len > SC_MAX_PATH_SIZE)
		return SC_ERROR_INVALID_ARGUMENTS;
	memcpy(dest->value + dest->len, src->value, src->len);
	dest->len += src->len;
	return 0;
}

int sc_append_path_id(struct sc_path *dest, const u8 *id, size_t idlen)
{
	if (dest->len + idlen > SC_MAX_PATH_SIZE)
		return SC_ERROR_INVALID_ARGUMENTS;
	memcpy(dest->value + dest->len, id, idlen);
	dest->len += idlen;
	return 0;
}

const char *sc_print_path(const sc_path_t *path)
{
	static char	buffer[64];
	size_t		n, len;

	buffer[0] = '\0';
	if ((len = path->len) >= sizeof(buffer)/2)
		len = sizeof(buffer)/2;
	for (n = 0; n < len; n++)
		sprintf(buffer + 2*n, "%02x", path->value[n]);

	return buffer;
}

int sc_file_add_acl_entry(struct sc_file *file, unsigned int operation,
                          unsigned int method, unsigned long key_ref)
{
	struct sc_acl_entry *p, *_new;

	assert(file != NULL);
	assert(operation < SC_MAX_AC_OPS);

	switch (method) {
	case SC_AC_NEVER:
		sc_file_clear_acl_entries(file, operation);
		file->acl[operation] = (struct sc_acl_entry *) 1;
		return 0;
	case SC_AC_NONE:
		sc_file_clear_acl_entries(file, operation);
		file->acl[operation] = (struct sc_acl_entry *) 2;
		return 0;
	case SC_AC_UNKNOWN:
		sc_file_clear_acl_entries(file, operation);
		file->acl[operation] = (struct sc_acl_entry *) 3;
		return 0;
	default:
		/* NONE and UNKNOWN get zapped when a new AC is added.
		 * If the ACL is NEVER, additional entries will be
		 * dropped silently. */
		if (file->acl[operation] == (struct sc_acl_entry *) 1)
			return 0;
		if (file->acl[operation] == (struct sc_acl_entry *) 2
		 || file->acl[operation] == (struct sc_acl_entry *) 3)
			file->acl[operation] = NULL;
	}
	
	_new = (struct sc_acl_entry *) malloc(sizeof(struct sc_acl_entry));
	if (_new == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	_new->method = method;
	_new->key_ref = key_ref;
	_new->next = NULL;

	p = file->acl[operation];
	if (p == NULL) {
		file->acl[operation] = _new;
		return 0;
	}
	while (p->next != NULL)
		p = p->next;
	p->next = _new;

	return 0;
}

const struct sc_acl_entry * sc_file_get_acl_entry(const struct sc_file *file,
						  unsigned int operation)
{
	struct sc_acl_entry *p;
	static const struct sc_acl_entry e_never = {
		SC_AC_NEVER, SC_AC_KEY_REF_NONE, NULL
	};
	static const struct sc_acl_entry e_none = {
		SC_AC_NONE, SC_AC_KEY_REF_NONE, NULL
	};
	static const struct sc_acl_entry e_unknown = {
		SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE, NULL
	};

	assert(file != NULL);
	assert(operation < SC_MAX_AC_OPS);

	p = file->acl[operation];
	if (p == (struct sc_acl_entry *) 1)
		return &e_never;
	if (p == (struct sc_acl_entry *) 2)
		return &e_none;
	if (p == (struct sc_acl_entry *) 3)
		return &e_unknown;

	return file->acl[operation];
}

void sc_file_clear_acl_entries(struct sc_file *file, unsigned int operation)
{
	struct sc_acl_entry *e;
	
	assert(file != NULL);
	assert(operation < SC_MAX_AC_OPS);

	e = file->acl[operation];
	if (e == (struct sc_acl_entry *) 1 || 
	    e == (struct sc_acl_entry *) 2 ||
	    e == (struct sc_acl_entry *) 3) {
		file->acl[operation] = NULL;
		return;
	}

	while (e != NULL) {
		struct sc_acl_entry *tmp = e->next;
		free(e);
		e = tmp;
	}
	file->acl[operation] = NULL;
}

struct sc_file * sc_file_new()
{
	struct sc_file *file = (struct sc_file *) malloc(sizeof(struct sc_file));
	
	if (file == NULL)
		return NULL;
	memset(file, 0, sizeof(struct sc_file));
	file->magic = SC_FILE_MAGIC;
	return file;
}

void sc_file_free(struct sc_file *file)
{
	int i;
	assert(sc_file_valid(file));
	file->magic = 0;
	for (i = 0; i < SC_MAX_AC_OPS; i++)
		sc_file_clear_acl_entries(file, i);
	if (file->sec_attr)
		free(file->sec_attr);
	if (file->prop_attr)
		free(file->prop_attr);
	if (file->type_attr)
		free(file->type_attr);
	free(file);
}

void sc_file_dup(struct sc_file **dest, const struct sc_file *src)
{
	struct sc_file *newf;
	const struct sc_acl_entry *e;
	int op;
	
	assert(sc_file_valid(src));
	*dest = NULL;
	newf = sc_file_new();
	if (newf == NULL)
		return;
	*dest = newf;
	
	*newf = *src;
	for (op = 0; op < SC_MAX_AC_OPS; op++) {
		newf->acl[op] = NULL;
		e = sc_file_get_acl_entry(src, op);
		if (e != NULL)
			sc_file_add_acl_entry(newf, op, e->method, e->key_ref);
	}
}

int sc_file_set_sec_attr(struct sc_file *file, const u8 *sec_attr,
			 size_t sec_attr_len)
{
	assert(sc_file_valid(file));

	if (sec_attr == NULL) {
		if (file->sec_attr != NULL)
			free(file->sec_attr);
		file->sec_attr = NULL;
		file->sec_attr_len = 0;
		return 0;
	 }
	file->sec_attr = (u8 *) realloc(file->sec_attr, sec_attr_len);
	if (file->sec_attr == NULL) {
		file->sec_attr_len = 0;
		return SC_ERROR_OUT_OF_MEMORY;
	}
	memcpy(file->sec_attr, sec_attr, sec_attr_len);
	file->sec_attr_len = sec_attr_len;

	return 0;
}                         

int sc_file_set_prop_attr(struct sc_file *file, const u8 *prop_attr,
			 size_t prop_attr_len)
{
	assert(sc_file_valid(file));

	if (prop_attr == NULL) {
		if (file->prop_attr != NULL)
			free(file->prop_attr);
		file->prop_attr = NULL;
		file->prop_attr_len = 0;
		return 0;
	 }
	file->prop_attr = (u8 *) realloc(file->prop_attr, prop_attr_len);
	if (file->prop_attr == NULL) {
		file->prop_attr_len = 0;
		return SC_ERROR_OUT_OF_MEMORY;
	}
	memcpy(file->prop_attr, prop_attr, prop_attr_len);
	file->prop_attr_len = prop_attr_len;

	return 0;
}                         

int sc_file_set_type_attr(struct sc_file *file, const u8 *type_attr,
			 size_t type_attr_len)
{
	assert(sc_file_valid(file));

	if (type_attr == NULL) {
		if (file->type_attr != NULL)
			free(file->type_attr);
		file->type_attr = NULL;
		file->type_attr_len = 0;
		return 0;
	 }
	file->type_attr = (u8 *) realloc(file->type_attr, type_attr_len);
	if (file->type_attr == NULL) {
		file->type_attr_len = 0;
		return SC_ERROR_OUT_OF_MEMORY;
	}
	memcpy(file->type_attr, type_attr, type_attr_len);
	file->type_attr_len = type_attr_len;

	return 0;
}                         

inline int sc_file_valid(const struct sc_file *file) {
#ifndef NDEBUG
	assert(file != NULL);
#endif
	return file->magic == SC_FILE_MAGIC;
}

int _sc_parse_atr(struct sc_context *ctx, struct sc_slot_info *slot)
{
	u8 *p = slot->atr;
	int atr_len = (int) slot->atr_len;
	int n_hist, x;
	int tx[4];
	int i, FI, DI;
	const int Fi_table[] = {
		372, 372, 558, 744, 1116, 1488, 1860, -1,
		-1, 512, 768, 1024, 1536, 2048, -1, -1 };
	const int f_table[] = {
		40, 50, 60, 80, 120, 160, 200, -1,
		-1, 50, 75, 100, 150, 200, -1, -1 };
	const int Di_table[] = {
		-1, 1, 2, 4, 8, 16, 32, -1,
		12, 20, -1, -1, -1, -1, -1, -1 };

	slot->atr_info.hist_bytes_len = 0;
	slot->atr_info.hist_bytes = NULL;

	if (atr_len == 0) {
		sc_error(ctx, "empty ATR - card not present?\n");
		return SC_ERROR_INTERNAL;
	}

	if (p[0] != 0x3B && p[0] != 0x3F) {
		sc_error(ctx, "invalid sync byte in ATR: 0x%02X\n", p[0]);
		return SC_ERROR_INTERNAL;
	}
	n_hist = p[1] & 0x0F;
	x = p[1] >> 4;
	p += 2;
	atr_len -= 2;
	for (i = 0; i < 4 && atr_len > 0; i++) {
                if (x & (1 << i)) {
                        tx[i] = *p;
                        p++;
                        atr_len--;
                } else
                        tx[i] = -1;
        }
	if (tx[0] >= 0) {
		slot->atr_info.FI = FI = tx[0] >> 4;
		slot->atr_info.DI = DI = tx[0] & 0x0F;
		slot->atr_info.Fi = Fi_table[FI];
		slot->atr_info.f = f_table[FI];
		slot->atr_info.Di = Di_table[DI];
	} else {
		slot->atr_info.Fi = -1;
		slot->atr_info.f = -1;
		slot->atr_info.Di = -1;
	}
	if (tx[2] >= 0)
		slot->atr_info.N = tx[3];
	else
		slot->atr_info.N = -1;
	while (tx[3] > 0 && tx[3] & 0xF0 && atr_len > 0) {
		x = tx[3] >> 4;
		for (i = 0; i < 4 && atr_len > 0; i++) {
	                if (x & (1 << i)) {
	                        tx[i] = *p;
	                        p++;
	                        atr_len--;
	                } else
	                        tx[i] = -1;
        	}
	}
	if (atr_len <= 0)
		return 0;
	if (n_hist > atr_len)
		n_hist = atr_len;
	slot->atr_info.hist_bytes_len = n_hist;
	slot->atr_info.hist_bytes = p;
	
	return 0;
}
