/*
 * jacartapki.h: Support for JaCarta PKI applet
 *
 * Copyright (C) 2025  Andrey Khodunov <a.khodunov@aladdin.ru>
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
#ifndef _SM_JACARTAPKI_H
#define _SM_JACARTAPKI_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(ENABLE_SM)

int jacartapki_sm_chv_change(struct sc_card *card, struct sc_pin_cmd_data *data, unsigned chv_ref,
		int *tries_left, unsigned op_acl);
int jacartapki_sm_encrypt_des_cbc3(struct sc_context *ctx, unsigned char *key,
		unsigned char *in, size_t in_len,
		unsigned char **out, size_t *out_len, int not_force_pad);
int jacartapki_iso_sm_open(struct sc_card *card);
int jacartapki_iso_sm_get_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu);
int jacartapki_iso_sm_free_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu);
int jacartapki_iso_sm_close(struct sc_card *card);

#endif

#ifdef __cplusplus
}
#endif
#endif
