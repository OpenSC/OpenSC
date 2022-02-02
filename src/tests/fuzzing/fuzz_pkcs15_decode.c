/*
 * Copyright (C) 2019 Frank Morgner <frankmorgner@gmail.com>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "fuzzer_reader.h"
#include "libopensc/pkcs15.h"
#include "libopensc/internal.h"


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	size_t i = 0;
	struct sc_reader *reader = NULL;
	const uint8_t *buf;
	uint16_t buf_len;
	static struct sc_context *ctx = NULL;
	static struct sc_pkcs15_card *p15card = NULL;
	static sc_card_t *card = NULL;
	struct sc_pkcs15_tokeninfo *tokeninfo = NULL;
	int (* decode_entries[])(struct sc_pkcs15_card *, struct sc_pkcs15_object *,
			const u8 **nbuf, size_t *nbufsize) = {
		sc_pkcs15_decode_prkdf_entry, sc_pkcs15_decode_pukdf_entry,
		sc_pkcs15_decode_skdf_entry, sc_pkcs15_decode_cdf_entry,
		sc_pkcs15_decode_dodf_entry, sc_pkcs15_decode_aodf_entry
	};
	int algorithms[] = { SC_ALGORITHM_RSA, SC_ALGORITHM_EC, SC_ALGORITHM_GOSTR3410, SC_ALGORITHM_EDDSA };

	/* Establish context for fuzz app*/
	sc_establish_context(&ctx, "fuzz");
	if (!ctx)
		return 0;

	/* Erase possible readers from ctx */
	while (list_size(&ctx->readers)) {
		sc_reader_t *rdr = (sc_reader_t *) list_get_at(&ctx->readers, 0);
		_sc_delete_reader(ctx, rdr);
	}
	if (ctx->reader_driver->ops->finish != NULL)
		ctx->reader_driver->ops->finish(ctx);

	/* Create virtual reader */
	ctx->reader_driver = sc_get_fuzz_driver();
	fuzz_add_reader(ctx, Data, Size);
	reader = sc_ctx_get_reader(ctx, 0);

	/* Connect card to reader */
	if (sc_connect_card(reader, &card)) {
		sc_release_context(ctx);
		return 0;
	}

	sc_pkcs15_bind(card, NULL, &p15card);
	if (!p15card)
		goto err;

	for (i = 0; i < sizeof decode_entries/sizeof *decode_entries; i++) {
		struct sc_pkcs15_object *obj;
		const u8 *p = NULL;
		size_t len = 0;
		if (!(obj = calloc(1, sizeof *obj)))
			goto err;
		fuzz_get_chunk(reader, &buf, &buf_len);
		p = buf;
		len = (size_t) buf_len;
		while (SC_SUCCESS == decode_entries[i](p15card, obj, &p, (size_t *) &len)) {
			sc_pkcs15_free_object(obj);
			if (!(obj = calloc(1, sizeof *obj)))
				goto err;
		}
		sc_pkcs15_free_object(obj);
	}

	fuzz_get_chunk(reader, &buf, &buf_len);
	for (i = 0; i < 4; i++) {
		struct sc_pkcs15_pubkey *pubkey = calloc(1, sizeof *pubkey);
		if (!pubkey)
			goto err;
		pubkey->algorithm = algorithms[i];
		sc_pkcs15_decode_pubkey(ctx, pubkey, buf, buf_len);
		sc_pkcs15_free_pubkey(pubkey);
	}

	fuzz_get_chunk(reader, &buf, &buf_len);
	tokeninfo = sc_pkcs15_tokeninfo_new();
	sc_pkcs15_parse_tokeninfo(ctx, tokeninfo, buf, buf_len);
	sc_pkcs15_free_tokeninfo(tokeninfo);

	fuzz_get_chunk(reader, &buf, &buf_len);
	sc_pkcs15_parse_unusedspace(buf, buf_len, p15card);

	sc_pkcs15_card_free(p15card);

err:
	sc_disconnect_card(card);
	sc_release_context(ctx);
	return 0;
}
