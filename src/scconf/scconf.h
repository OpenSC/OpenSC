/*
 * $Id$
 *
 * Copyright (C) 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
 *
 * Originally based on source by Timo Sirainen <tss@iki.fi>
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

#ifndef _SC_CONF_H
#define _SC_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

#define SCCONF_BOOLEAN		11
#define SCCONF_INTEGER		12
#define SCCONF_STRING		13

typedef struct _scconf_block scconf_block;

typedef struct _scconf_list {
	struct _scconf_list *next;
	char *data;
} scconf_list;

#define SCCONF_ITEM_TYPE_COMMENT	0	/* key = NULL, comment */
#define SCCONF_ITEM_TYPE_BLOCK		1	/* key = key, block */
#define SCCONF_ITEM_TYPE_VALUE		2	/* key = key, list */

typedef struct _scconf_item {
	struct _scconf_item *next;
	int type;
	char *key;
	union {
		char *comment;
		scconf_block *block;
		scconf_list *list;
	} value;
} scconf_item;

struct _scconf_block {
	scconf_block *parent;
	scconf_list *name;
	scconf_item *items;
};

typedef struct {
	char *filename;
	int debug;
	scconf_block *root;
	char *errmsg;
} scconf_context;

/* Allocate scconf_context
 * The filename can be NULL
 */
extern scconf_context *scconf_new(const char *filename);

/* Free scconf_context
 */
extern void scconf_free(scconf_context * config);

/* Parse configuration
 * Returns 1 = ok, 0 = error, -1 = error opening config file
 */
extern int scconf_parse(scconf_context * config);

/* Parse a static configuration string
 * Returns 1 = ok, 0 = error
 */
extern int scconf_parse_string(scconf_context * config, const char *string);

/* Write config to a file
 * If the filename is NULL, use the config->filename
 * Returns 0 = ok, else = errno
 */
extern int scconf_write(scconf_context * config, const char *filename);

/* Find a block by the item_name
 * If the block is NULL, the root block is used
 */
extern const scconf_block *scconf_find_block(const scconf_context * config, const scconf_block * block, const char *item_name);

/* Find blocks by the item_name
 * If the block is NULL, the root block is used
 * The key can be used to specify what the blocks first name should be
 */
extern scconf_block **scconf_find_blocks(const scconf_context * config, const scconf_block * block, const char *item_name, const char *key);

/* Get a list of values for option
 */
extern const scconf_list *scconf_find_list(const scconf_block * block, const char *option);

/* Return the first string of the option
 * If no option found, return def
 */
extern const char *scconf_get_str(const scconf_block * block, const char *option, const char *def);

/* Return the first value of the option as integer
 * If no option found, return def
 */
extern int scconf_get_int(const scconf_block * block, const char *option, int def);

/* Return the first value of the option as boolean
 * If no option found, return def
 */
extern int scconf_get_bool(const scconf_block * block, const char *option, int def);

/* Write value to a block as a string
 */
extern const char *scconf_put_str(scconf_block * block, const char *option, const char *value);

/* Write value to a block as an integer
 */
extern int scconf_put_int(scconf_block * block, const char *option, int value);

/* Write value to a block as a boolean
 */
extern int scconf_put_bool(scconf_block * block, const char *option, int value);

/* Add block structure
 * If the block is NULL, the root block is used
 */
extern scconf_block *scconf_block_add(scconf_context * config, scconf_block * block, const char *key, const scconf_list *name);

/* Copy block structure (recursive)
 */
extern scconf_block *scconf_block_copy(const scconf_block * src, scconf_block ** dst);

/* Free block structure (recursive)
 */
extern void scconf_block_destroy(scconf_block * block);

/* Add item to block structure
 * If the block is NULL, the root block is used
 */
extern scconf_item *scconf_item_add(scconf_context * config, scconf_block * block, scconf_item * item, int type, const char *key, const void *data);

/* Copy item structure (recursive)
 */
extern scconf_item *scconf_item_copy(const scconf_item * src, scconf_item ** dst);

/* Free item structure (recursive)
 */
extern void scconf_item_destroy(scconf_item * item);

/* Add a new value to the list
 */
extern scconf_list *scconf_list_add(scconf_list ** list, const char *value);

/* Copy list structure
 */
extern scconf_list *scconf_list_copy(const scconf_list * src, scconf_list ** dst);

/* Free list structure
 */
extern void scconf_list_destroy(scconf_list * list);

/* Return the length of an list array
 */
extern int scconf_list_array_length(const scconf_list * list);

/* Return the combined length of the strings on all arrays
 */
extern int scconf_list_strings_length(const scconf_list * list);

/* Return an allocated string that contains all
 * the strings in a list separated by the filler
 * The filler can be NULL
 */
extern char *scconf_list_strdup(const scconf_list * list, const char *filler);

/* Returns an allocated array of const char *pointers to
 * list elements.
 * Last pointer is NULL
 * Array must be freed, but pointers to strings belong to scconf_list
 */
extern const char **scconf_list_toarray(const scconf_list * list);

#ifdef __cplusplus
}
#endif
#endif
