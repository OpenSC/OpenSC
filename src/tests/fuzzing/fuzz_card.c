/*
 * fuzz_card.c: Fuzzer for sc_* functions
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


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	sc_context_t     *ctx = NULL;
	sc_card_t        *card = NULL;
	struct sc_reader *reader = NULL;
	unsigned long     flag = 0;
	const uint8_t    *ptr = NULL;
	uint16_t          ptr_size = 0;
	u8                files[SC_MAX_EXT_APDU_BUFFER_SIZE];
	uint8_t           len = 0;
	u8               *rnd = NULL, *wrap_buf = NULL, *unwrap_buf = NULL;
	size_t            wrap_buf_len = 0, unwrap_buf_len = 0;
	int               r = 0;

#ifdef FUZZING_ENABLED
	fclose(stdout);
#endif

	if (size <= sizeof(unsigned long) + 1)
		return 0;

	flag = *((unsigned long *) data);
	len = *(data + sizeof(unsigned long));
	data += (sizeof(unsigned long) + sizeof(uint8_t));
	size -= (sizeof(unsigned long) + sizeof(uint8_t));

	/* Establish context for fuzz app*/
	sc_establish_context(&ctx, "fuzz");
	if (!ctx)
		return 0;

	if (fuzz_connect_card(ctx, &card, &reader, data, size) != SC_SUCCESS)
		goto err;

	/* Wrap & Unwrap*/
	if (!(wrap_buf = malloc(SC_MAX_APDU_BUFFER_SIZE)))
		goto err;
	wrap_buf_len = SC_MAX_APDU_BUFFER_SIZE;
	sc_wrap(card, NULL, 0, wrap_buf, wrap_buf_len);

	fuzz_get_chunk(reader, &ptr, &ptr_size);
	if (!(unwrap_buf = malloc(ptr_size)))
		goto err;
	memcpy(unwrap_buf, ptr, ptr_size);
	unwrap_buf_len = ptr_size;
	sc_unwrap(card, unwrap_buf, unwrap_buf_len, NULL, 0);

	/* Write binary  */
	sc_write_binary(card, 0, ptr, ptr_size, flag);

	/* Put data */
	fuzz_get_chunk(reader, &ptr, &ptr_size);
	sc_put_data(card, (unsigned int)flag, ptr, ptr_size);

	/* List files */
	sc_list_files(card, files, sizeof(files));

	/* Get challenge */
	rnd = malloc(len);
	if (rnd == NULL)
		goto err;
	if ((r = sc_get_challenge(card, rnd, len)) != SC_SUCCESS)
		sc_log(ctx, "sc_get_challenge failed with rc = %d", r);

	/* Append record */
	sc_append_record(card, ptr, ptr_size, flag);

err:
	free(rnd);
	free(wrap_buf);
	free(unwrap_buf);
	sc_disconnect_card(card);
	sc_release_context(ctx);
	return 0;
}
