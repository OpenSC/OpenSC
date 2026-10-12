/*
 * Copyright (C) 2017 Frank Morgner <frankmorgner@gmail.com>
 *
 * This file is part of OpenSC.
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "egk-tool-cmdline.h"
#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "util.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

/*
 * References:
 *
 * Speicherstrukturen der eGK für Gesundheitsanwendungen version 1.6.0 from 18.03.2008
 * https://fachportal.gematik.de/fileadmin/user_upload/fachportal/files/Spezifikationen/Basis-Rollout/Elektronische_Gesundheitskarte/gematik_eGK_Speicherstrukturen_V1_6_0.pdf
 *
 * Spezifikation der elektronischen Gesundheitskarte eGK-Objektsystem version 4.5.0 from 02.10.2019
 * https://fachportal.gematik.de/fachportal-import/files/gemSpec_eGK_ObjSys_G2_1_V4.5.0.pdf
 *
 * Speicherstrukturen der eGK für die Fachanwendung VSDM version 1.2.1 from 19.02.2021
 * https://fachportal.gematik.de/fachportal-import/files/gemSpec_eGK_Fach_VSDM_V1.2.1.pdf
 *
 * Speicherstrukturen der eGK für die Fachanwendung AMTS version 1.2.0 from 26.10.2018
 * https://www.vesta-gematik.de/standard/formhandler/324/gemSpec_eGK_Fach_AMTS_V1_2_0.pdf
 */

void dump_binary(const void *buf, size_t buf_len)
{
	if (!buf || buf_len == 0)
		return;
#ifdef _WIN32
	_setmode(fileno(stdout), _O_BINARY);
#endif
	fwrite(buf, 1, buf_len, stdout);
#ifdef _WIN32
	_setmode(fileno(stdout), _O_TEXT);
#endif
}

#ifdef ENABLE_ZLIB
#include <zlib.h>

int uncompress_gzip(void* uncompressed, size_t *uncompressed_len,
		const void* compressed, size_t compressed_len)
{
	z_stream stream;
	int ret;

	if (!uncompressed || !uncompressed_len || !compressed || compressed_len == 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	memset(&stream, 0, sizeof stream);
	stream.total_in = compressed_len;
	stream.avail_in = (uInt)compressed_len;
	stream.total_out = *uncompressed_len;
	stream.avail_out = (uInt)*uncompressed_len;
	stream.next_in = (Bytef *) compressed;
	stream.next_out = (Bytef *) uncompressed;

	/* 15 window bits, and the +32 tells zlib to to detect if using gzip or zlib */
	if (inflateInit2(&stream, (15 + 32)) != Z_OK) {
		return SC_ERROR_INVALID_DATA;
	}
	ret = inflate(&stream, Z_FINISH);
	if (ret != Z_STREAM_END) {
		inflateEnd(&stream);
		return SC_ERROR_INVALID_DATA;
	}
	*uncompressed_len = stream.total_out;
	inflateEnd(&stream);

	return SC_SUCCESS;
}

static void dump_decompressed_or_raw(const void *data, size_t len)
{
	z_stream stream;
	unsigned char *buf = NULL, *tmp;
	size_t buf_size = 4096;
	int ret;

	if (!data || len == 0)
		return;

	buf = (unsigned char *)malloc(buf_size);
	if (!buf) {
		dump_binary(data, len);
		return;
	}

	memset(&stream, 0, sizeof(stream));
	stream.avail_in = (uInt)len;
	stream.next_in = (Bytef *)data;
	stream.avail_out = (uInt)buf_size;
	stream.next_out = buf;

	if (inflateInit2(&stream, (15 + 32)) != Z_OK) {
		free(buf);
		dump_binary(data, len);
		return;
	}

	while ((ret = inflate(&stream, Z_NO_FLUSH)) == Z_OK) {
		if (stream.avail_out == 0) {
			size_t prev_size = buf_size;
			if (buf_size > (size_t)1024 * 1024) {
				ret = Z_MEM_ERROR;
				break;
			}
			buf_size *= 2;
			tmp = (unsigned char *)realloc(buf, buf_size);
			if (!tmp) {
				ret = Z_MEM_ERROR;
				break;
			}
			buf = tmp;
			stream.avail_out = (uInt)(buf_size - prev_size);
			stream.next_out = buf + prev_size;
		}
	}

	if (ret == Z_STREAM_END) {
		dump_binary(buf, (size_t)stream.total_out);
	} else {
		dump_binary(data, len);
	}

	inflateEnd(&stream);
	free(buf);
}
#else
int uncompress_gzip(void* uncompressed, size_t *uncompressed_len,
		const void* compressed, size_t compressed_len)
{
	if (!uncompressed || !uncompressed_len || !compressed)
		return SC_ERROR_INVALID_ARGUMENTS;
	return SC_ERROR_NOT_SUPPORTED;
}

static void dump_decompressed_or_raw(const void *data, size_t len)
{
	dump_binary(data, len);
}
#endif

#define PRINT(c) (isprint((unsigned char)(c)) ? (c) : '?')

const unsigned char aid_hca[] = {0xD2, 0x76, 0x00, 0x00, 0x01, 0x02};
static const char *app_name = "egk-tool";

int read_file(struct sc_card *card, char *str_path, unsigned char **data, size_t *data_len)
{
	struct sc_path path;
	struct sc_file *file = NULL;
	unsigned char *p;
	int ok = 0;
	int r;
	size_t len;

	if (!str_path || !data || !data_len)
		return 0;

	sc_format_path(str_path, &path);
	if (SC_SUCCESS != sc_select_file(card, &path, &file)) {
		goto err;
	}

	len = file && file->size > 0 ? file->size : 4096;
	p = (unsigned char *)realloc(*data, len);
	if (!p) {
		goto err;
	}
	*data = p;
	*data_len = len;

	r = sc_read_binary(card, 0, p, len, 0);
	if (r < 0)
		goto err;

	*data_len = (size_t)r;
	ok = 1;

err:
	sc_file_free(file);

	return ok;
}

void decode_version(const unsigned char *bcd, unsigned int *major, unsigned int *minor, unsigned int *fix)
{
	if (!bcd || !major || !minor || !fix)
		return;

	*major = 0;
	*minor = 0;
	*fix = 0;

	/* decode BCD to decimal */
	if ((bcd[0]>>4) < 10 && ((bcd[0]&0xF) < 10) && ((bcd[1]>>4) < 10)) {
		*major = (bcd[0]>>4)*100 + (bcd[0]&0xF)*10 + (bcd[1]>>4);
	}
	if (((bcd[1]&0xF) < 10) && ((bcd[2]>>4) < 10) && ((bcd[2]&0xF) < 10)) {
		*minor = (bcd[1]&0xF)*100 + (bcd[2]>>4)*10 + (bcd[2]&0xF);
	}
	if ((bcd[3]>>4) < 10 && ((bcd[3]&0xF) < 10)
			&& (bcd[4]>>4) < 10 && ((bcd[4]&0xF) < 10)) {
		*fix = (bcd[3]>>4)*1000 + (bcd[3]&0xF)*100
			+ (bcd[4]>>4)*10 + (bcd[4]&0xF);
	}
}

int
main (int argc, char **argv)
{
	struct gengetopt_args_info cmdline;
	struct sc_path path;
	struct sc_context *ctx = NULL;
	struct sc_card *card = NULL;
	unsigned char *data = NULL;
	size_t data_len = 0;
	int r;
	int exit_status = EXIT_SUCCESS;
	sc_context_param_t ctx_param;

	if (cmdline_parser(argc, argv, &cmdline) != 0)
		return 1;

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;
	ctx_param.debug    = cmdline.verbose_given;
	if (cmdline.verbose_given > 1)
		ctx_param.debug_file = stderr;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		cmdline_parser_free(&cmdline);
		return 1;
	}

	r = util_connect_card_ex(ctx, &card, cmdline.reader_arg, 0, 0);
	if (r) {
		exit_status = EXIT_FAILURE;
		goto err;
	}

	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, aid_hca, sizeof aid_hca, 0, 0);
	if (SC_SUCCESS != sc_select_file(card, &path, NULL)) {
		exit_status = EXIT_FAILURE;
		goto err;
	}

	if (cmdline.pd_flag) {
		if (read_file(card, "iD001", &data, &data_len) && data_len >= 2) {
			size_t len_pd = (data[0] << 8) | data[1];

			if (len_pd + 2 <= data_len) {
				dump_decompressed_or_raw(data + 2, len_pd);
			} else {
				exit_status = EXIT_FAILURE;
			}
		} else {
			exit_status = EXIT_FAILURE;
		}
	}

	if (cmdline.vd_flag || cmdline.gvd_flag) {
		if (read_file(card, "iD002", &data, &data_len) && data_len >= 8) {
			size_t off_vd  = (data[0] << 8) | data[1];
			size_t end_vd  = (data[2] << 8) | data[3];
			size_t off_gvd = (data[4] << 8) | data[5];
			size_t end_gvd = (data[6] << 8) | data[7];

			if (off_vd <= end_vd && end_vd < data_len
					&& off_gvd <= end_gvd && end_gvd < data_len) {
				size_t len_vd = end_vd - off_vd + 1;
				size_t len_gvd = end_gvd - off_gvd + 1;

				if (cmdline.vd_flag) {
					dump_decompressed_or_raw(data + off_vd, len_vd);
				}

				if (cmdline.gvd_flag) {
					dump_decompressed_or_raw(data + off_gvd, len_gvd);
				}
			} else {
				exit_status = EXIT_FAILURE;
			}
		} else {
			exit_status = EXIT_FAILURE;
		}
	}

	if (cmdline.vsd_status_flag) {
		if (read_file(card, "iD00C", &data, &data_len) && data_len >= 25) {
			const char *status;
			unsigned int major, minor, fix;

			switch (data[0]) {
				case '0':
					status = "Transactions pending";
					break;
				case '1':
					status = "No transactions pending";
					break;
				default:
					status = "Unknown";
					break;
			}

			decode_version(data+15, &major, &minor, &fix);

			printf(
					"Status      %s\n"
					"Timestamp   %c%c.%c%c.%c%c%c%c at %c%c:%c%c:%c%c\n"
					"Version     %u.%u.%u\n",
					status,
					PRINT(data[7]), PRINT(data[8]),
					PRINT(data[5]), PRINT(data[6]),
					PRINT(data[1]), PRINT(data[2]), PRINT(data[3]), PRINT(data[4]),
					PRINT(data[9]), PRINT(data[10]),
					PRINT(data[11]), PRINT(data[12]),
					PRINT(data[13]), PRINT(data[14]),
					major, minor, fix);
		} else {
			exit_status = EXIT_FAILURE;
		}
	}

err:
	free(data);
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_release_context(ctx);
	cmdline_parser_free (&cmdline);

	return exit_status;
}
