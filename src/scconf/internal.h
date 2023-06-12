/*
 * $Id$
 *
 * Copyright (C) 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _SCCONF_INTERNAL_H
#define _SCCONF_INTERNAL_H

#include "scconf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TOKEN_TYPE_COMMENT	0
#define TOKEN_TYPE_NEWLINE	1
#define TOKEN_TYPE_STRING	2
#define TOKEN_TYPE_PUNCT	3

#define DEPTH_LIMIT 16

typedef struct _scconf_parser {
	scconf_context *config;

	scconf_block *block;
	scconf_item *last_item, *current_item;

	char *key;
	scconf_list *name;

	int state;
	int last_token_type;
	int line;

	unsigned int error:1;
	unsigned int warnings:1;
	char emesg[256];
	size_t nested_blocks;
} scconf_parser;

extern int scconf_lex_parse(scconf_parser * parser, const char *filename);
extern int scconf_lex_parse_string(scconf_parser * parser,
				   const char *config_string);
extern void scconf_skip_block(scconf_parser * parser);
extern void scconf_parse_token(scconf_parser * parser, int token_type, const char *token);

#ifdef __cplusplus
}
#endif
#endif
