/*
 * internal.h: Internal definitions for libopensc
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

#ifndef _SC_INTERNAL_H
#define _SC_INTERNAL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "opensc.h"
#include "log.h"
#include "ui.h"
#include "cards.h"
#include <assert.h>

#define SC_FILE_MAGIC			0x14426950
#define SC_CARD_MAGIC			0x27182818
#define SC_CTX_MAGIC			0x0A550335

struct sc_atr_table {
	/* The atr fields are required to
	 * be in aa:bb:cc hex format. */
	char *atr;
	/* The atrmask is logically AND'd with an
	 * card atr prior to comparison with the
	 * atr reference value above. */
	char *atrmask;
	char *name;
	int type;
	unsigned long flags;
	/* Reference to card_atr configuration block,
	 * available to user configured card entries. */
	scconf_block *card_atr;
};

/* Internal use only */
int sc_check_sw(struct sc_card *card, unsigned int sw1, unsigned int sw2);

int _sc_add_reader(struct sc_context *ctx, struct sc_reader *reader);
int _sc_parse_atr(struct sc_context *ctx, struct sc_slot_info *slot);
struct sc_slot_info *_sc_get_slot_info(struct sc_reader *reader, int slot_id);

/* Add an ATR to the card driver's struct sc_atr_table */
int _sc_add_atr(struct sc_context *ctx, struct sc_card_driver *driver, struct sc_atr_table *src);
int _sc_free_atr(struct sc_context *ctx, struct sc_card_driver *driver);

/* Returns an scconf_block entry with matching ATR/ATRmask to the ATR specified,
 * NULL otherwise. Additionally, if card driver is not specified, search through
 * all card drivers user configured ATRs. */
scconf_block *_sc_match_atr_block(sc_context_t *ctx, struct sc_card_driver *driver, u8 *atr, size_t atr_len);

/* Returns an index number if a match was found, -1 otherwise. table has to
 * be null terminated. */
int _sc_match_atr(struct sc_card *card, struct sc_atr_table *table, int *type_out);

int _sc_check_forced_protocol(struct sc_context *ctx, u8 *atr, size_t atr_len, unsigned int *protocol);

int _sc_card_add_algorithm(struct sc_card *card, const struct sc_algorithm_info *info);
int _sc_card_add_rsa_alg(struct sc_card *card, unsigned int key_length,
			 unsigned long flags, unsigned long exponent);
struct sc_algorithm_info * _sc_card_find_rsa_alg(struct sc_card *card,
						 unsigned int key_length);

int sc_asn1_read_tag(const u8 ** buf, size_t buflen, unsigned int *cla_out,
		     unsigned int *tag_out, size_t *taglen);

scconf_block *_get_conf_block(sc_context_t *ctx, const char *name1, const char *name2, int priority);

#ifdef __cplusplus
}
#endif

#endif
