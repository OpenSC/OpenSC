/*
 * fuzz_pkcs15_encode.c: Fuzzer for encoding functions
 *
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * Author: Veronika Hanulikova <vhanulik@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fuzzer_reader.h"
#include "libopensc/pkcs15.h"
#include "libopensc/internal.h"


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	struct sc_context       *ctx = NULL;
	struct sc_card          *card = NULL;
	struct sc_pkcs15_card   *p15card = NULL;
	struct sc_pkcs15_object *obj;
	unsigned char           *unused_space = NULL;
	size_t                   unused_space_len = 0;

	sc_establish_context(&ctx, "fuzz");
	if (!ctx)
		return 0;

	if (fuzz_connect_card(ctx, &card, NULL, Data, Size) != SC_SUCCESS)
		goto err;

	if (sc_pkcs15_bind(card, NULL, &p15card) != 0)
		goto err;

	for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
		u8 *buf = NULL;
		size_t buf_len = 0;
		struct sc_pkcs15_object *key_object = NULL;
		sc_pkcs15_pubkey_t *pkey = NULL;
		switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
		case SC_PKCS15_TYPE_PUBKEY:
			sc_pkcs15_encode_pukdf_entry(ctx, obj, &buf, &buf_len);
			sc_pkcs15_read_pubkey(p15card, obj, &pkey);
			sc_pkcs15_free_pubkey(pkey);
			break;
		case SC_PKCS15_TYPE_PRKEY:
			sc_pkcs15_encode_prkdf_entry(ctx, obj, &buf, &buf_len);
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			sc_pkcs15_encode_dodf_entry(ctx, obj, &buf, &buf_len);
			break;
		case SC_PKCS15_TYPE_SKEY:
			sc_pkcs15_encode_skdf_entry(ctx, obj, &buf, &buf_len);
			break;
		case SC_PKCS15_TYPE_AUTH:
			sc_pkcs15_encode_aodf_entry(ctx, obj, &buf, &buf_len);
			break;
		case SC_PKCS15_TYPE_CERT:
			sc_pkcs15_encode_cdf_entry(ctx, obj, &buf, &buf_len);
			sc_pkcs15_prkey_attrs_from_cert(p15card, obj, &key_object);
			break;
		}
		free(buf);
	}
	sc_pkcs15_encode_unusedspace(ctx, p15card, &unused_space, &unused_space_len);
	free(unused_space);

err:
	sc_pkcs15_card_free(p15card);
	sc_disconnect_card(card);
	sc_release_context(ctx);

	return 0;
}
