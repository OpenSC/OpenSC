/*
 * pkcs15-syn.c: PKCS #15 emulation of non-pkcs15 cards
 *
 * Copyright (C) 2003  Olaf Kirch <okir@suse.de>
 *               2004  Nils Larsch <nlarsch@betrusted.com>
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

#ifndef PKCS15_SYN_H
#define PKCS15_SYN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libopensc/types.h>
#include <libopensc/pkcs15.h>

int sc_pkcs15emu_westcos_init_ex(sc_pkcs15_card_t *p15card,	struct sc_aid *);
int sc_pkcs15emu_openpgp_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_starcert_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_tcos_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_esteid_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_esteid2018_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_piv_init_ex(sc_pkcs15_card_t *p15card,	struct sc_aid *);
int sc_pkcs15emu_cac_init_ex(sc_pkcs15_card_t *p15card,	struct sc_aid *);
int sc_pkcs15emu_gemsafeGPK_init_ex(sc_pkcs15_card_t *p15card,	struct sc_aid *);
int sc_pkcs15emu_gemsafeV1_init_ex(sc_pkcs15_card_t *p15card,	struct sc_aid *);
int sc_pkcs15emu_actalis_init_ex(sc_pkcs15_card_t *p15card,	struct sc_aid *);
int sc_pkcs15emu_atrust_acos_init_ex(sc_pkcs15_card_t *p15card,	struct sc_aid *);
int sc_pkcs15emu_tccardos_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_entersafe_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_pteid_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_oberthur_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_itacns_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_sc_hsm_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_dnie_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_gids_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_iasecc_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_jpki_init_ex(sc_pkcs15_card_t *,	struct sc_aid *);
int sc_pkcs15emu_coolkey_init_ex(sc_pkcs15_card_t *p15card,	struct sc_aid *);
int sc_pkcs15emu_din_66291_init_ex(sc_pkcs15_card_t *p15card,	struct sc_aid *);

struct sc_pkcs15_emulator_handler {
	const char *name;
	int (*handler)(sc_pkcs15_card_t *, struct sc_aid *);
};

#ifdef __cplusplus
}
#endif

#endif
