/*
 * pkcs15-laser.c: Support for JaCarta PKI applet
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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ENABLE_OPENSSL /* empty file without openssl */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/compat_strlcpy.h"
#include "aux-data.h"
#include "cardctl.h"
#include "cards.h"
#include "laser.h"
#include "log.h"
#include "pkcs15.h"
#include "pkcs11/pkcs11.h"

#include <openssl/sha.h>

#define LOG_ERROR_GOTO(ctx, r, text) \
	do { \
		int _ret = (r); \
		sc_do_log_color(ctx, SC_LOG_DEBUG_NORMAL, FILENAME, __LINE__, __FUNCTION__, SC_COLOR_FG_RED, \
				"%s: %d (%s)\n", (text), (_ret), sc_strerror(_ret)); \
		goto err; \
	} while (0)

#define PATH_APPLICATION   "3F003000"
#define PATH_TOKENINFO	   "3F003000C000"
#define PATH_PUBLICDIR	   "3F0030003001"
#define PATH_PRIVATEDIR	   "3F0030003002"
#define PATH_MINIDRIVERDIR "3F0030003003"
#define PATH_USERPIN	   "3F000020"
#define PATH_SOPIN	   "3F000010"

#define LASER_BASEKX_MASK    0x7F00
#define LASER_TYPE_KX_CERT   0x11
#define LASER_TYPE_KX_PRVKEY 0x12
#define LASER_TYPE_KX_PUBKEY 0x13
#define LASER_TYPE_KX_SKEY   0x14
#define LASER_TYPE_KX_DATA   0x15
#define LASER_TYPE_CERT	     0x20
#define LASER_TYPE_PRVKEY    0x30
#define LASER_TYPE_PUBKEY    0x40
#define LASER_TYPE_SKEY	     0x50
#define LASER_TYPE_DATA	     0x60

struct laser_ko_props {
	unsigned char class;
	unsigned char usage;
	unsigned char algorithm;
	unsigned char padding;
	struct {
		unsigned char retry_byte;
		unsigned char unlock_byte;
	} auth_attrs;
	struct {
		unsigned char min_length;
		unsigned char max_length;
		unsigned char upper_case;
		unsigned char lower_case;
		unsigned char digits;
		unsigned char alphas;
		unsigned char specials;
		unsigned char occurrence;
		unsigned char sequence;
	} pin_policy;
};

int sc_pkcs15emu_laser_init_ex(struct sc_pkcs15_card *, struct sc_aid *aid);

static int
_laser_type(int id)
{
	if ((id & 0xFF00) == 0x0) {
		if ((id & 0xC0 /*LASER_FS_REF_MASK*/) == LASER_FS_BASEFID_PUBKEY)
			return LASER_TYPE_PUBKEY;
		else
			return LASER_TYPE_PRVKEY;
	}

	switch (id & LASER_BASEKX_MASK) {
	case 0x0100:
		return LASER_TYPE_KX_PUBKEY;
	case 0x0200:
		return LASER_TYPE_KX_PRVKEY;
	case 0x0300:
		return LASER_TYPE_KX_SKEY;
	case 0x0400:
	case 0x0500:
		return LASER_TYPE_KX_CERT;
	case 0x0600:
		return LASER_TYPE_KX_DATA;
	}

	return -1;
}

static int
_alloc_ck_string(const unsigned char *data, size_t max_len, char **out)
{
	char *str = NULL;
	size_t idx;

	if (!out)
		return SC_ERROR_INVALID_ARGUMENTS;

	str = calloc(1, max_len + 1);

	if (!str)
		return SC_ERROR_OUT_OF_MEMORY;

	memcpy(str, data, max_len);

	for (idx = strlen(str); idx && str[--idx] == ' ';)
		str[idx] = '\0';

	if (*out != NULL)
		free(*out);

	*out = strdup(str);

	free(str);
	return SC_SUCCESS;
}

static int
_create_pin(struct sc_pkcs15_card *p15card, char *label,
		char *pin_path, unsigned char auth_id, unsigned flags)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object pin_obj;
	struct sc_pkcs15_auth_info auth_info;
	struct sc_path path;
	struct sc_file *file = NULL;
	struct laser_ko_props *props = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Create PIN '%s', path '%s'", label, pin_path);

	memset(&auth_info, 0, sizeof(auth_info));
	memset(&pin_obj, 0, sizeof(pin_obj));

	sc_format_path(pin_path, &path);
	rv = sc_select_file(p15card->card, &path, &file);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot select USER PIN");

	if (!file->prop_attr_len)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_DATA, "No PIN attributes in FCP");
	sc_log(ctx, "FCP User PIN attributes '%s'", sc_dump_hex(file->prop_attr, file->prop_attr_len));

	props = (struct laser_ko_props *)file->prop_attr;

	auth_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	auth_info.auth_method = (auth_id == LASER_TRANSPORT_PIN1_AUTH_ID) ? SC_AC_AUT : SC_AC_CHV;
	auth_info.auth_id.value[0] = auth_id;
	auth_info.auth_id.len = 1;
	auth_info.attrs.pin.reference = path.value[path.len - 1];

	auth_info.attrs.pin.flags = flags;
	auth_info.attrs.pin.flags |= SC_PKCS15_PIN_FLAG_INITIALIZED;
	auth_info.attrs.pin.flags |= SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA;
	auth_info.attrs.pin.flags |= SC_PKCS15_PIN_FLAG_CASE_SENSITIVE;

	/* Not imposed by card */
	auth_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;

	auth_info.attrs.pin.min_length = props->pin_policy.min_length;
	auth_info.attrs.pin.max_length = props->pin_policy.max_length;
	auth_info.attrs.pin.stored_length = props->pin_policy.max_length;
	auth_info.attrs.pin.pad_char = 0xff;
	auth_info.tries_left = (props->auth_attrs.retry_byte >> 4) & 0x0F;

	strlcpy(pin_obj.label, label, sizeof(pin_obj.label));
	pin_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;
	rv = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &auth_info);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to create PIN PKCS#15 object");
err:
	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}

int
sc_pkcs15emu_laser_create_pin(struct sc_pkcs15_card *p15card, char *label,
		char *pin_path, unsigned char auth_id, unsigned flags)
{
	return _create_pin(p15card, label, pin_path, auth_id, flags);
}

static int
_create_certificate(struct sc_pkcs15_card *p15card, unsigned file_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object obj;
	struct sc_pkcs15_cert_info info;
	unsigned char fid[2] = {((file_id >> 8) & 0xFF), (file_id & 0xFF)};
	unsigned char *data = NULL;
	size_t len;
	unsigned char sha1[SHA_DIGEST_LENGTH], sha1_attr[SHA_DIGEST_LENGTH];
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(&info, 0, sizeof(info));
	memset(&obj, 0, sizeof(obj));

	sc_format_path(PATH_PUBLICDIR, &info.path);
	sc_append_path_id(&info.path, fid, sizeof(fid));

	rv = sc_pkcs15_read_file(p15card, &info.path, &data, &len, 0);
	LOG_TEST_RET(ctx, rv, "Error while getting file content.");

	if (len < 11) /* header 7 bytes, tail 4 bytes */
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_DATA, "certificate attributes file is too short");

	rv = laser_attrs_cert_decode(ctx, &obj, &info, data + 7, len - 11);
	LOG_TEST_GOTO_ERR(ctx, rv, "Decode certificate attributes error.");

	rv = sc_pkcs15emu_add_x509_cert(p15card, &obj, &info);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to emu-add certificate object");

	memcpy(sha1_attr, data + 12, SHA_DIGEST_LENGTH);
	memset(data + 12, 0, SHA_DIGEST_LENGTH);
	SHA1(data, len, sha1);

	if (memcmp(sha1, sha1_attr, SHA_DIGEST_LENGTH))
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_DATA, "invalid checksum of certificate attributes");
err:
	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
_create_pubkey(struct sc_pkcs15_card *p15card, unsigned file_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object obj;
	struct sc_pkcs15_pubkey_info info;
	struct sc_pkcs15_pubkey_rsa key_rsa;
	struct sc_file *key_file = NULL;
	unsigned ko_fid = ((file_id & LASER_FS_REF_MASK) | LASER_FS_BASEFID_PUBKEY) + 1;
	struct sc_path path;
	unsigned char fid[2] = {((file_id >> 8) & 0xFF), (file_id & 0xFF)};
	unsigned char *data = NULL;
	size_t len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(&info, 0, sizeof(info));
	memset(&obj, 0, sizeof(obj));
	memset(&key_rsa, 0, sizeof(key_rsa));

	sc_format_path(PATH_PUBLICDIR, &path);
	sc_append_path_id(&path, fid, sizeof(fid));

	rv = sc_pkcs15_read_file(p15card, &path, &data, &len, 0);
	LOG_TEST_GOTO_ERR(ctx, rv, "Error while getting file content.");

	if (len < 11) /* header 7 bytes, tail 4 bytes */
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_DATA, "invalid length of public key attributes data");

	/* set info path to public key KO */
	path.value[path.len - 2] = (ko_fid >> 8) & 0xFF;
	path.value[path.len - 1] = ko_fid & 0xFF;
	info.path = path;
	info.key_reference = ko_fid & 0xFF;

	rv = sc_select_file(p15card->card, &info.path, &key_file);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot select key file");

	info.modulus_length = key_file->size * 8;
	sc_file_free(key_file);

	info.native = 1;

	/* ignore header and tail */
	rv = laser_attrs_pubkey_decode(ctx, &obj, &info, data + 7, len - 11);
	LOG_TEST_GOTO_ERR(ctx, rv, "Decode public key attributes error.");

	if (!info.id.len) {
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_NOT_IMPLEMENTED, "Missing public key ID");
	}

	rv = sc_pkcs15emu_add_rsa_pubkey(p15card, &obj, &info);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to emu-add public key object");

	sc_log(ctx, "Key path %s", sc_print_path(&info.path));
err:
	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
_create_prvkey(struct sc_pkcs15_card *p15card, unsigned file_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object obj, *pobj = NULL;
	struct sc_pkcs15_prkey_info info, *pinfo = NULL;
	struct sc_pkcs15_prkey_rsa key_rsa;
	struct sc_file *key_file = NULL;
	unsigned ko_fid = ((file_id & LASER_FS_REF_MASK) | LASER_FS_BASEFID_PRVKEY_EXCH) + 1;
	struct sc_path path;
	unsigned char fid[2] = {((file_id >> 8) & 0xFF), (file_id & 0xFF)};
	unsigned char *data = NULL;
	size_t len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	sc_log(ctx, "create PKCS#15 private key object. FID:%X, KID:%X", file_id, ko_fid);
	memset(&info, 0, sizeof(info));
	memset(&obj, 0, sizeof(obj));
	memset(&key_rsa, 0, sizeof(key_rsa));

	sc_format_path(PATH_PRIVATEDIR, &path);
	sc_append_path_id(&path, fid, sizeof(fid));

	rv = sc_pkcs15_read_file(p15card, &path, &data, &len, 0);
	LOG_TEST_GOTO_ERR(ctx, rv, "Error while getting file content.");

	if (len < 11) /* header 7 bytes, tail 4 bytes */
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_DATA, "private key attributes file is too short");

	/* set info path to private key KO */
	path.value[path.len - 2] = ko_fid / 0x100;
	path.value[path.len - 1] = ko_fid % 0x100;
	info.path = path;
	info.key_reference = ko_fid % 0x100;

	rv = sc_select_file(p15card->card, &info.path, &key_file);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot select key file");

	info.modulus_length = key_file->size * 8;
	sc_file_free(key_file);
	key_file = NULL;

	info.native = 1;

	/* ignore header 7 bytes and tail 4 bytes */
	rv = laser_attrs_prvkey_decode(ctx, &obj, &info, data + 7, len - 11);
	LOG_TEST_GOTO_ERR(ctx, rv, "Decode private key attributes error.");

	if (!info.id.len)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_NOT_IMPLEMENTED, "Missing private key ID");

	obj.auth_id.len = 1;
	obj.auth_id.value[0] = LASER_USER_PIN_AUTH_ID;

	rv = sc_pkcs15emu_add_rsa_prkey(p15card, &obj, &info);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to emu-add private key object");

	rv = sc_pkcs15_find_prkey_by_id(p15card, &info.id, &pobj);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get new key object");

	pinfo = (struct sc_pkcs15_prkey_info *)pobj->data;

	if (pinfo->aux_data != NULL && (pinfo->aux_data->type != SC_AUX_DATA_TYPE_MD_CMAP_RECORD && pinfo->aux_data->type != SC_AUX_DATA_TYPE_NO_DATA))
		sc_aux_data_free(&pinfo->aux_data);
	if (pinfo->aux_data == NULL) {
		rv = sc_aux_data_allocate(ctx, &pinfo->aux_data, NULL);
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot allocate MD auxiliary data");
	}

	if (pinfo->aux_data->type != SC_AUX_DATA_TYPE_MD_CMAP_RECORD || pinfo->aux_data->data.cmap_record.guid_len == 0) {
		unsigned char guid[40];
		size_t guid_len;

		sc_log(ctx, "Key path %s", sc_print_path(&pinfo->path));
		memset(guid, 0, sizeof(guid));
		guid_len = sizeof(guid);

		rv = sc_pkcs15_get_object_guid(p15card, pobj, 1, guid, &guid_len);
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get private key GUID");

		guid[guid_len] = 0;
		rv = sc_aux_data_set_md_guid(ctx, pinfo->aux_data, (char *)guid);
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot set MD CMAP Guid");
	}

	sc_log(ctx, "Key path %s", sc_print_path(&pinfo->path));

	unsigned char guid[SC_PKCS15_MAX_ID_SIZE];
	size_t guid_len = sizeof(guid);
	rv = sc_aux_data_get_md_guid(ctx, pinfo->aux_data, 1, guid, &guid_len);
	if (rv == SC_SUCCESS)
		sc_log(ctx, "Key GUID 0x'%s'", sc_dump_hex(guid, guid_len));
err:
	sc_file_free(key_file);
	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
_create_data_object(struct sc_pkcs15_card *p15card, const char *path, unsigned file_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object obj;
	struct sc_pkcs15_data_info info;
	unsigned char fid[2] = {((file_id >> 8) & 0xFF), (file_id & 0xFF)};
	unsigned char *data = NULL;
	size_t len;
	int rv;
	unsigned char hash_exists = 0;

	LOG_FUNC_CALLED(ctx);

	memset(&info, 0, sizeof(info));
	memset(&obj, 0, sizeof(obj));

	sc_format_path(path, &info.path);
	sc_append_path_id(&info.path, fid, sizeof(fid));

	rv = sc_pkcs15_read_file(p15card, &info.path, &data, &len, 0);

	// TEMP P15 DF RELOAD PRIVATE - not load private data-objects // TODO check error for read access denied
	if (rv != SC_SUCCESS)
		return SC_SUCCESS;

	if (len < 11) /* header 7 bytes, tail 4 bytes */
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_DATA, "data object file is too short");

	rv = laser_attrs_data_object_decode(ctx, &obj, &info, data + 7, len - 11, &hash_exists);
	LOG_TEST_GOTO_ERR(ctx, rv, "Decode data object error.");

	if ((obj.flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0) {
		// TEMP P15 DF RELOAD PRIVATE
		obj.auth_id.len = 1;
		obj.auth_id.value[0] = LASER_USER_PIN_AUTH_ID;
	}

	rv = sc_pkcs15emu_add_data_object(p15card, &obj, &info);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to emu-add data object");

	if (hash_exists) {
		unsigned char sha1_attr[SHA_DIGEST_LENGTH];

		memcpy(sha1_attr, data + 12, SHA_DIGEST_LENGTH);
		memset(data + 12, 0, SHA_DIGEST_LENGTH);

		// TEMP - disable check SHA for 0-filled hash
		if (memcmp(sha1_attr, data + 12, SHA_DIGEST_LENGTH)) {
			unsigned char sha1[SHA_DIGEST_LENGTH];

			SHA1(data, len, sha1);
			if (memcmp(sha1, sha1_attr, SHA_DIGEST_LENGTH)) {
				LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_DATA, "invalid checksum of DATA attributes");
			}
		}
	}
err:
	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
_parse_fs_data(struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
	size_t ii;
	char *df_paths[3] = {PATH_PUBLICDIR, PATH_PRIVATEDIR, NULL};
	int rv = SC_SUCCESS;
	int df;
	struct sc_pkcs15_object *pubkeys[12], *dobjs[12];
	size_t pubkeys_num, dobjs_num;
	struct sc_pkcs15_data *data = NULL;
	struct laser_cmap_record *rec = NULL;

	LOG_FUNC_CALLED(ctx);

	// TEMP P15 DF RELOAD PRIVATE
	// Add folder for data-objects manually for reload private data-objects in laser_parse_df after login.
	// If not add folder manually, it will be added automatically and the "enumerated" flag will be set to true
	// consequently laser_parse_df will not be called.
	struct sc_path path_private_df;
	sc_format_path(PATH_PRIVATEDIR, &path_private_df);
	sc_pkcs15_add_df(p15card, SC_PKCS15_DODF, &path_private_df);

	for (df = 0; df_paths[df]; df++) {
		struct sc_path path;
		size_t count;

		sc_format_path(df_paths[df], &path);
		rv = sc_select_file(card, &path, NULL);
		LOG_TEST_RET(ctx, rv, "Cannot select object's DF");

		rv = sc_list_files(card, buf, sizeof(buf));
		LOG_TEST_RET(ctx, rv, "'List file' error in object's DF");

		count = rv / 2;
		/* TODO:
		 * Laser's EF may have the 'DF name' attribute.
		 * Normally here this attribute has to be used to identify
		 * the kxc and kxs files.
		 * But, for a while, for the sake of simplicity,
		 * the FID/mask (0x0400/0xFFF0) is used instead.
		 */
		for (ii = 0; ii < count; ii++) {
			unsigned fid, type;

			fid = (*(buf + ii * 2) << 8) + *(buf + ii * 2 + 1);
			type = _laser_type(fid);
			sc_log(ctx, "parse FID:%04X, type:0x%04X", fid, type);
			switch (type) {
			case LASER_TYPE_KX_PRVKEY:
				sc_log(ctx, "parse private key attributes FID:%04X", fid);
				rv = _create_prvkey(p15card, fid);
				if (rv != SC_ERROR_NOT_IMPLEMENTED) /* ignore keys without ID */
					LOG_TEST_RET(ctx, rv, "Cannot create private key PKCS#15 object");
				break;
			case LASER_TYPE_KX_CERT:
				sc_log(ctx, "parse certificate attributes FID:%04X", fid);
				rv = _create_certificate(p15card, fid);
				LOG_TEST_RET(ctx, rv, "Cannot create certificate PKCS#15 object");
				break;
			case LASER_TYPE_KX_PUBKEY:
				sc_log(ctx, "parse public key attributes FID:%04X", fid);
				rv = _create_pubkey(p15card, fid);
				if (rv != SC_ERROR_NOT_IMPLEMENTED) /* ignore keys without ID */
					LOG_TEST_RET(ctx, rv, "Cannot create public key PKCS#15 object");
				break;
			case LASER_TYPE_KX_DATA:
				// TEMP P15 DF RELOAD PRIVATE - not load private data-objects
				if (strcmp(PATH_PRIVATEDIR, df_paths[df])) {
					sc_log(ctx, "parse data object attributes FID:%04X", fid);
					rv = _create_data_object(p15card, df_paths[df], fid);

					// TEMP skip data file creation error
					if (rv != SC_SUCCESS) {
						const char *err_s = sc_strerror(rv);
						sc_log(ctx, "create data PKCS#15 object error: %s", err_s);
						continue;
					}

					LOG_TEST_RET(ctx, rv, "Cannot create data PKCS#15 object");
				}
				break;
			default:
				break;
			}
		}
	}

	pubkeys_num = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PUBKEY, pubkeys, 12);
	sc_log(ctx, "Number of public keys %zu", pubkeys_num);
	for (ii = 0; ii < pubkeys_num; ii++) {
		struct sc_pkcs15_pubkey_info *info = (struct sc_pkcs15_pubkey_info *)pubkeys[ii]->data;
		struct sc_pkcs15_object *prkey_obj = NULL;

		if (!sc_pkcs15_find_prkey_by_id(p15card, &info->id, &prkey_obj))
			if (strlen(prkey_obj->label) && !strlen(pubkeys[ii]->label))
				memcpy(pubkeys[ii]->label, prkey_obj->label, sizeof(pubkeys[ii]->label));
	}

	dobjs_num = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT, dobjs, 12);
	for (ii = 0; ii < dobjs_num; ii++) {
		const struct sc_pkcs15_data_info *dinfo = (const struct sc_pkcs15_data_info *)dobjs[ii]->data;
		struct sc_pkcs15_object *prkeys[12];
		size_t prkeys_num, offs = 0;
		int rec_num;

		if (strcmp(dobjs[ii]->label, "cmapfile") || strcmp(dinfo->app_label, CMAP_DO_APPLICATION_NAME))
			continue;

		prkeys_num = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, prkeys, 12);
		LOG_TEST_GOTO_ERR(ctx, prkeys_num, "Failed to get private key objects");
		if (prkeys_num == 0)
			break;

		rv = sc_pkcs15_read_data_object(p15card, dinfo, 0, &data);
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot create data PKCS#15 object");

		sc_log(ctx, "Use '%s' DATA object to update private key MD data", dobjs[ii]->label);
		for (offs = 0, rec_num = 0; offs < data->data_len; rec_num++) {
			rv = laser_md_cmap_record_decode(ctx, data, &offs, &rec);
			LOG_TEST_GOTO_ERR(ctx, rv, "Failed to decode CMAP entry");
			if (!rec)
				break;
			if (rec->keysize_sign || rec->keysize_keyexchange) {
				unsigned char *guid = NULL;
				size_t guid_len = 0;

				rv = laser_md_cmap_record_guid(ctx, rec, &guid, &guid_len);
				LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get GUID string");
				sc_log(ctx, "CMAP record(%i) GUID 0x'%s'", rec_num, sc_dump_hex(guid, guid_len));

				for (ii = 0; ii < prkeys_num; ii++) {
					struct sc_pkcs15_prkey_info *info = (struct sc_pkcs15_prkey_info *)prkeys[ii]->data;
					int key_idx = (info->key_reference & LASER_FS_REF_MASK) - LASER_FS_KEY_REF_MIN;

					// sc_log(ctx, "Key(ref:0x%lX) GUID %s", info->key_reference, info->cmap_record.guid);
					sc_log(ctx, "Key(ref:0x%X)", info->key_reference);
					if (rec_num == key_idx) {

						if (info->aux_data != NULL && info->aux_data->type != SC_AUX_DATA_TYPE_MD_CMAP_RECORD && info->aux_data->type != SC_AUX_DATA_TYPE_NO_DATA)
							sc_aux_data_free(&info->aux_data);
						if (info->aux_data == NULL) {
							rv = sc_aux_data_allocate(ctx, &info->aux_data, NULL);
							LOG_TEST_GOTO_ERR(ctx, rv, "Cannot allocate MD auxiliary data");
						}

						guid[guid_len] = 0;
						rv = sc_aux_data_set_md_guid(ctx, info->aux_data, (char *)guid);
						LOG_TEST_GOTO_ERR(ctx, rv, "Cannot set MD CMAP Guid");

						info->aux_data->data.cmap_record.flags = rec->flags;
						info->aux_data->data.cmap_record.keysize_sign = rec->keysize_sign;
						info->aux_data->data.cmap_record.keysize_keyexchange = rec->keysize_keyexchange;

						sc_log(ctx, "Updated MD container data: flags:0x%X, sign-size %i, keyexchange-size %i",
								info->aux_data->data.cmap_record.flags, info->aux_data->data.cmap_record.keysize_sign,
								info->aux_data->data.cmap_record.keysize_keyexchange);
						break;
					}
				}
				if (ii == prkeys_num) {
					LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_DATA, "CMAP record without corresponding PKCS#15 private key object");
				}
			}

			free(rec);
			rec = NULL;
		}

		sc_pkcs15_free_data_object(data);
		data = NULL;
		break;
	}
err:
	free(rec);
	sc_pkcs15_free_data_object(data);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
_set_md_data(struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_SUCCESS;
	struct sc_path path;
	unsigned char *buf = NULL;
	size_t buflen = 0;
	unsigned char cardcf_fid[2] = {0x40, 0x01}; // 4001

	LOG_FUNC_CALLED(ctx);

	sc_format_path(PATH_MINIDRIVERDIR, &path);
	sc_append_path_id(&path, cardcf_fid, sizeof(cardcf_fid));

	rv = sc_pkcs15_read_file(p15card, &path, &buf, &buflen, 0);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot select&read laser-md-cardcf file");
	if ((int)sizeof(struct laser_cardcf) > buflen)
		LOG_ERROR_GOTO(ctx, 0 > rv ? rv : (rv = SC_ERROR_INVALID_DATA), "Incorrect laser-md-cardcf file");

	p15card->md_data = (struct sc_md_data *)calloc(1, sizeof(struct sc_md_data));

	if (!p15card->md_data)
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);

	p15card->md_data->cardcf = *((struct laser_cardcf *)buf);
err:
	free(buf);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
sc_pkcs15emu_laser_init(struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_path path;
	unsigned char *buf = NULL;
	size_t buflen = 0;
	int rv = SC_SUCCESS;
	const size_t labelSize = 32;
	const size_t manufactureIdSize = 32;
	const size_t modelSize = 16;
	const size_t serialNumberSize = 16;
	const size_t flagsSize = 4;
	const size_t countersSize = 4 * 10;
	size_t idx = 0;

	LOG_FUNC_CALLED(ctx);

	sc_format_path(PATH_TOKENINFO, &path);
	rv = sc_pkcs15_read_file(p15card, &path, &buf, &buflen, 0);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot select&read TOKEN-INFO file");

	if (buflen < LASER_TOKEN_INFO_LENGTH)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_DATA, "Invalid TOKEN-INFO data");

	rv = _alloc_ck_string(buf + idx, labelSize, &p15card->tokeninfo->label);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot allocate token label");
	idx += labelSize;

	rv = _alloc_ck_string(buf + idx, manufactureIdSize, &p15card->tokeninfo->manufacturer_id);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot allocate manufacturerID");
	idx += manufactureIdSize;
	idx += modelSize;

	rv = _alloc_ck_string(buf + idx, 16, &p15card->tokeninfo->serial_number);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot allocate serialNumber");
	idx += serialNumberSize;

	p15card->tokeninfo->version = 0;
	p15card->tokeninfo->flags = *((int32_t *)(buf + idx));
	idx += (flagsSize + countersSize);

	p15card->card->version.hw_major = *(buf + idx++);
	p15card->card->version.hw_minor = *(buf + idx++);
	p15card->card->version.fw_major = *(buf + idx++);
	p15card->card->version.fw_minor = *(buf + idx++);

	if (p15card->tokeninfo->flags & CKF_USER_PIN_INITIALIZED) {
		rv = _create_pin(p15card, "User PIN", PATH_USERPIN, LASER_USER_PIN_AUTH_ID, 0);
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot create 'User PIN' object");
	}

	rv = _create_pin(p15card, "SO PIN", PATH_SOPIN, LASER_SO_PIN_AUTH_ID, SC_PKCS15_PIN_FLAG_SO_PIN);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot create 'SO PIN' object");

	rv = _parse_fs_data(p15card);
	LOG_TEST_GOTO_ERR(ctx, rv, "Error while creating 'certificate' objects");

	rv = _set_md_data(p15card);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot set MD data");
err:
	free(buf);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
laser_detect_card(sc_pkcs15_card_t *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;

	sc_log(ctx, "laser_detect_card (%s)", card->name);
	if (card->type != SC_CARD_TYPE_ALADDIN_LASER)
		return SC_ERROR_WRONG_CARD;

	return SC_SUCCESS;
}

// TEMP P15 DF RELOAD PRIVATE
// Called from C_Login only if (userType == CKU_USER)
static int
laser_parse_df(struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *pdf)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_path path;

	sc_format_path(PATH_PRIVATEDIR, &path);

	if (pdf->type != SC_PKCS15_DODF || !sc_compare_path(&path, &pdf->path))
		return sc_pkcs15_parse_df(p15card, pdf);
	if (pdf->enumerated)
		return SC_SUCCESS;

	unsigned char user_logged_in = 0;
	struct laser_private_data *private_data = (struct laser_private_data *)p15card->card->drv_data;
	if (private_data) {
		for (int i = 0; i != sizeof(private_data->auth_state) / sizeof(private_data->auth_state[0]); i++) {
			if (private_data->auth_state[i].pin_reference == LASER_USER_PIN_REFERENCE) {
				user_logged_in = private_data->auth_state[i].logged_in;
				break;
			}
		}
	}
	if (!user_logged_in)
		return SC_SUCCESS;

	unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
	size_t ii, count;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = sc_select_file(card, &path, NULL);
	LOG_TEST_RET(ctx, rv, "Cannot select object's DF");

	rv = sc_list_files(card, buf, sizeof(buf));
	LOG_TEST_RET(ctx, rv, "'List file' error in object's DF");

	count = rv / 2;
	/* TODO:
	 * Laser's EF may have the 'DF name' attribute.
	 * Normally here this attribute has to be used to identify
	 * the kxc and kxs files.
	 * But, for a while, for the sake of simplicity,
	 * the FID/mask (0x0400/0xFFF0) is used instead.
	 */
	for (ii = 0; ii < count; ii++) {
		unsigned fid, type;

		fid = *(buf + ii * 2) * 0x100 + *(buf + ii * 2 + 1);
		type = _laser_type(fid);
		sc_log(ctx, "parse FID:%04X, type:0x%04X", fid, type);
		switch (type) {
		case LASER_TYPE_KX_DATA:
			sc_log(ctx, "parse data object attributes FID:%04X", fid);
			rv = _create_data_object(p15card, PATH_PRIVATEDIR, fid);
			LOG_TEST_RET(ctx, rv, "Cannot create data PKCS#15 object");
			break;
		default:
			break;
		}
	}

	pdf->enumerated = 1;
	return SC_SUCCESS;
}

static void
laser_clear(struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	LOG_FUNC_CALLED(ctx);
}

int
sc_pkcs15emu_laser_init_ex(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = laser_detect_card(p15card);
	LOG_TEST_RET(ctx, rv, "Not JaCarta PKI token/card");

	// P15 DF RELOAD PRIVATE
	p15card->ops.parse_df = laser_parse_df;
	p15card->ops.clear = laser_clear;

	rv = sc_pkcs15emu_laser_init(p15card);
	LOG_TEST_RET(ctx, rv, "Internal JaCarta PKI PKCS#15 error");

	LOG_FUNC_RETURN(ctx, rv);
}

#endif //  ENABLE_OPENSSL
