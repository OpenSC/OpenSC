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

typedef struct _scconf_block scconf_block;

typedef struct _scconf_list {
	struct _scconf_list *next;
	char *data;
} scconf_list;

#define SCCONF_ITEM_TYPE_COMMENT	0	/* key = NULL, data = char *comment */
#define SCCONF_ITEM_TYPE_BLOCK		1	/* key = class, data = scconf_block */
#define SCCONF_ITEM_TYPE_VALUE		2	/* key = key, value = scconf_list */

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
	scconf_block *root;
} scconf_context;

/* Init configuration
 * The filename can be NULL
 */
extern scconf_context *scconf_init(const char *filename);

/* Free configuration
 */
extern void scconf_deinit(scconf_context * config);

/* Parse configuration
 * Returns 1 = ok, 0 = error, -1 = error opening config file
 */
extern int scconf_parse(scconf_context * config);

/* Write config to a file
 * If the filename is NULL, use the config->filename
 * Returns 0 = ok, else = errno
 */
extern int scconf_write(scconf_context * config, const char *filename);

/* Find a config by the item_name
 * If the block is NULL, the root block is used
 */
extern const scconf_block *scconf_find_block(scconf_context * config, const scconf_block * block, const char *item_name);

/* Find a config by the item_name
 * If the block is NULL, the root block is used
 * The key can be used to specify what the blocks first name should be.
 */
extern scconf_block **scconf_find_blocks(scconf_context * config, const scconf_block * block, const char *item_name, const char *key);

/* Get a list of values for option
 */
extern const scconf_list *scconf_find_value(const scconf_block * block, const char *option);

/* Return the first value of the option
 */
extern const char *scconf_find_value_first(const scconf_block * block, const char *option);

/* Free list structure
 */
extern void scconf_list_destroy(scconf_list * list);

/* Free block structure
 */
extern void scconf_block_destroy(scconf_block * block);

/* Return the length of an list array
 */
extern int scconf_list_array_length(const scconf_list * list);

/* Return the combined length of the strings on all arrays
 */
extern int scconf_list_strings_length(const scconf_list * list);

/* Return an allocated string that contains all
 * the strings in a list separated by the filler
 */
extern char *scconf_list_strdup(const scconf_list * list, const char *filler);

#ifdef __cplusplus
}
#endif
#endif
