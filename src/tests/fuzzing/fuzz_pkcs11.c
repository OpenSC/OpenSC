/*
 * fuzz_pkcs11.c: Fuzz target for PKCS #11 API
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

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11-opensc.h"
#include "pkcs11/sc-pkcs11.h"
#include "fuzzer_reader.h"
#include "fuzzer_tool.h"

#define SIG_LEN 512

/* If disabled, card is connected only via C_Initialize */
#define FUZZING 1

extern CK_FUNCTION_LIST_3_0 pkcs11_function_list_3_0;
static CK_FUNCTION_LIST_3_0_PTR p11 = NULL;

/* Values used for key template*/
static CK_BBOOL _true = TRUE;
static CK_BBOOL _false = FALSE;

/* Global parameters for key template */
CK_ULONG key_type = 0;
unsigned char ecparams[256];
unsigned char *opt_object_label[256];
CK_BYTE opt_object_id[100];
CK_MECHANISM_TYPE opt_allowed_mechanisms[20];

#if FUZZING 
static int fuzz_card_connect(const uint8_t *data, size_t size, sc_pkcs11_slot_t **slot_out)
{
	/* Works in the same manner as card_detect() for only one slot and card with virtual reader */
	struct sc_pkcs11_card *p11card = NULL;
	struct sc_reader *reader = NULL;
	struct sc_app_info *app_generic = NULL;
	sc_pkcs11_slot_t *slot = NULL;
	int rv = CKR_OK, free_p11card = 0;

	/* Erase possible virtual slots*/
	list_clear(&virtual_slots);

	/* Erase possible readers from context */
	while (list_size(&context->readers)) {
		sc_reader_t *rdr = (sc_reader_t *) list_get_at(&context->readers, 0);
		_sc_delete_reader(context, rdr);
	}
	if (context->reader_driver->ops->finish != NULL)
		context->reader_driver->ops->finish(context);

	/* Create virtual reader */
	context->reader_driver = sc_get_fuzz_driver();
	fuzz_add_reader(context, data, size);
	reader = sc_ctx_get_reader(context, 0);

	/* Add slot for reader */
	if (create_slot(reader) != CKR_OK) {
		goto fail;
	}

	/* Locate a slot related to the reader */
	for (size_t i = 0; i < list_size(&virtual_slots); i++) {
		slot = (sc_pkcs11_slot_t *) list_get_at(&virtual_slots, i);
		if (slot->reader == reader) {
			p11card = slot->p11card;
			break;
		}
	}

	/* Create p11card */
	p11card = (struct sc_pkcs11_card *)calloc(1, sizeof(struct sc_pkcs11_card));
	p11card->reader = reader;
	free_p11card = 1;

	/* Connect card to reader */
	if ((rv = sc_connect_card(reader, &p11card->card)) != SC_SUCCESS) {
		goto fail;
	}
	init_slot_info(&slot->slot_info, reader);

	/* Instead of detecting framework*/
	p11card->framework = &framework_pkcs15;

	/* Bind 'generic' application or (emulated?) card without applications */
	app_generic = sc_pkcs15_get_application_by_type(p11card->card, "generic");
	if (app_generic || !p11card->card->app_count) {
		scconf_block *conf_block = NULL;

		conf_block = sc_match_atr_block(p11card->card->ctx, NULL, &p11card->reader->atr);
		if (!conf_block) /* check default block */
			conf_block = sc_get_conf_block(context, "framework", "pkcs15", 1);

		rv = p11card->framework->bind(p11card, app_generic);
		if (rv != CKR_TOKEN_NOT_RECOGNIZED && rv != CKR_OK)
			goto fail;

		rv = p11card->framework->create_tokens(p11card, app_generic);
		if (rv != CKR_OK)
			goto fail;
		free_p11card = 0;
	}
	
	/* Bind rest of application*/
	for (int j = 0; j < p11card->card->app_count; j++)   {
		struct sc_app_info *app_info = p11card->card->app[j];

		if (app_generic && app_generic == p11card->card->app[j])
			continue;

		if (p11card->framework->bind(p11card, app_info) != CKR_OK) {
			continue;
		}
		rv = p11card->framework->create_tokens(p11card, app_info);
		if (rv != CKR_OK) {
			goto fail;
		}
		free_p11card = 0;
	}
	if (slot_out)
		*slot_out = slot;
fail:
	if (free_p11card) {
		sc_pkcs11_card_free(p11card);
	}
	return rv;
}
#endif

static int fuzz_pkcs11_initialize(const uint8_t *data, size_t size, sc_pkcs11_slot_t **slot_out, CK_SESSION_HANDLE *session)
{
	p11 = &pkcs11_function_list_3_0;

	context = NULL;
	memset(&sc_pkcs11_conf, 0, sizeof(struct sc_pkcs11_config));

	p11->C_Initialize(NULL);

	#if FUZZING
	/* fuzz target can connect to real card via C_Initialize */
	if (fuzz_card_connect(data, size, slot_out) != CKR_OK) {
		p11->C_Finalize(NULL);
		return CKR_GENERAL_ERROR;
	}
	#endif

	if (p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, session) != CKR_OK) {
		p11->C_Finalize(NULL);
		return CKR_GENERAL_ERROR;
	}
	return CKR_OK;
}

static int set_mechanism(const uint8_t **data, size_t *size, CK_MECHANISM *mech)
{
	if (*size < sizeof(unsigned long int))
		return 1;

	memset(mech, 0, sizeof(*mech));
	(*mech).mechanism = *((unsigned long int *)*data);
	*data += sizeof(unsigned long int);
	*size -= sizeof(unsigned long int);
	return 0;
}

static void test_change_pin(const unsigned char *data, size_t size)
{
	CK_SESSION_HANDLE session;
	CK_TOKEN_INFO     info;
	char             *pin = NULL;
	char             *new_pin = NULL;
	int               login_type = data[0];
	data++; size--;

	if (!(pin = extract_word(&data, &size)))
		goto end;
	if (!(new_pin = extract_word(&data, &size)))
		goto end;

	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;
	p11->C_GetTokenInfo(0, &info);
	p11->C_Login(session, login_type, (CK_UTF8CHAR *) pin, pin == NULL ? 0 : strlen(pin));
	p11->C_SetPIN(session,
		(CK_UTF8CHAR *) pin, pin == NULL ? 0 : strlen(pin),
		(CK_UTF8CHAR *) new_pin, new_pin == NULL ? 0 : strlen(new_pin));

	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(new_pin);
	free(pin);
}

static void test_init_pin(const unsigned char *data, size_t size)
{
	CK_SESSION_HANDLE session;
	CK_TOKEN_INFO     info;
	char             *pin = NULL;
	char             *so_pin = NULL;
	int               login_type = data[0];
	data++; size--;

	if (!(pin = extract_word(&data, &size)))
		goto end;
	if (!(so_pin = extract_word(&data, &size)))
		goto end;

	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;
	p11->C_GetTokenInfo(0, &info);
	p11->C_Login(session, login_type, (CK_UTF8CHAR *) so_pin, so_pin == NULL ? 0 : strlen(so_pin));
	p11->C_InitPIN(session, (CK_UTF8CHAR *) pin, pin == NULL ? 0 : strlen(pin));

	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(pin);
	free(so_pin);
}

static void test_init_token(const unsigned char *data, size_t size)
{
	CK_SESSION_HANDLE session;
	char             *pin = NULL;
	unsigned char    *label = NULL;
	size_t            label_len = 0;
	unsigned char     token_label[33];
	sc_pkcs11_slot_t *slot = NULL;
	/* token label must be padded with blank characters, and which must not be null-terminated*/
	memset(token_label, ' ', sizeof(token_label));

	if (!(pin = extract_word(&data, &size)))
		goto end;
	if (!(label = (unsigned char *) extract_word(&data, &size)))
		goto end;
	label_len = strlen((char *) label);
	memcpy(token_label, label, label_len < 33 ? label_len : 32);

	if (fuzz_pkcs11_initialize(data, size, &slot, &session) != CKR_OK)
		goto end;
	p11->C_InitToken(slot->id, (CK_UTF8CHAR *) pin, pin == NULL ? 0 : strlen(pin), token_label);

	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(pin);
	free(label);
}

static void test_random(const unsigned char *data, size_t size)
{
	CK_SESSION_HANDLE session;
	size_t            random_len = data[0];
	CK_BYTE           buf[256];
	data++; size--;

	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		return;

	p11->C_GenerateRandom(session, buf, random_len);

	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
}

static void test_digest_update(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE session;
	const uint8_t    *dig_data = NULL;
	size_t            dig_size = 0;
	CK_MECHANISM      mech = {0, NULL_PTR, 0};
	unsigned char     buffer[64] = {0};
	CK_ULONG          hash_len = sizeof(buffer);
	int               to_process = 0, rv = 0;

	if (set_mechanism(&data, &size, &mech))
		return;

	/* Copy data for hashing*/
	dig_data = data;
	if ((dig_size = get_buffer(&dig_data, size, &data, &size, 6000)) == 0)
		return;

	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		return;

	if (p11->C_DigestInit(session, &mech) != CKR_OK)
		goto end;

	while (dig_size > 0) {
		to_process = dig_size > sizeof(buffer) ? sizeof(buffer) : dig_size;
		dig_size -= to_process;
		memcpy(buffer, dig_data, to_process);
		dig_data += to_process;

		rv = p11->C_DigestUpdate(session, buffer, to_process);
		if (rv != CKR_OK)
			goto end;
	}
	hash_len = sizeof(buffer);
	p11->C_DigestFinal(session, buffer, &hash_len);

end:
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
}

void test_digest(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE session;
	const uint8_t    *ptr = NULL;
	unsigned char    *dig_data = NULL;
	size_t            dig_size = 0;
	CK_MECHANISM      mech = {0, NULL_PTR, 0};
	unsigned char     buffer[64] = {0};
	CK_ULONG          hash_len = sizeof(buffer);

	if (set_mechanism(&data, &size, &mech))
		return;

	/* Copy data for hashing*/
	ptr = data;
	if ((dig_size = get_buffer(&ptr, size, &data, &size, 6000)) == 0)
		return;
	if (!(dig_data = malloc(dig_size)))
		return;
	memcpy(dig_data, ptr, dig_size);

	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;

	if (p11->C_DigestInit(session, &mech) == CKR_OK)
		p11->C_Digest(session, dig_data, dig_size, buffer, &hash_len);

	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(dig_data);
}

static int fuzz_find_object(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS cls,
		CK_OBJECT_HANDLE_PTR ret, const unsigned char *id, size_t id_len)
{
	/* taken from tools/pkcs11-tool.c */
	CK_ATTRIBUTE attrs[2];
	unsigned int nattrs = 0;
	CK_ULONG     count = 0;

	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &cls;
	attrs[0].ulValueLen = sizeof(cls);
	nattrs++;
	if (id) {
		attrs[nattrs].type = CKA_ID;
		attrs[nattrs].pValue = (void *) id;
		attrs[nattrs].ulValueLen = id_len;
		nattrs++;
	}

	if (p11->C_FindObjectsInit(sess, attrs, nattrs) != CKR_OK)
		return -1;

	if (p11->C_FindObjects(sess, ret, 1, &count) != CKR_OK)
		return -1;

	if (count == 0)
		*ret = CK_INVALID_HANDLE;
	p11->C_FindObjectsFinal(sess);
	return count;
}

static void test_sign(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE    session;
	uint8_t              login_type = CKU_USER;
	char                *pin = NULL;
	const unsigned char *opt_id;
	size_t               opt_id_len = 0;
	const uint8_t       *sign_data = NULL;
	size_t               sign_data_size = 0;
	CK_OBJECT_HANDLE     key = CK_INVALID_HANDLE;
	unsigned char        in_buffer[1025], sig_buffer[512];
	CK_MECHANISM         mech = {0, NULL_PTR, 0};
	CK_ULONG             sig_len = sizeof(sig_buffer);
	size_t               to_process = 0;
	CK_TOKEN_INFO        info;

	/* Process options*/
	if (set_mechanism(&data, &size, &mech) || size < 3)
		return;
	login_type = data[0];
	data++; size--;
	if (!(pin = extract_word(&data, &size)))
		return;
	opt_id = data;
	opt_id_len = get_buffer(&opt_id, size, &data, &size, 256);

	/* Prepare buffer for signing */
	sign_data = data;
	if ((sign_data_size = get_buffer(&sign_data, size, &data, &size, 6000)) == 0)
		goto end;

	/* Initialize */
	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;
	p11->C_GetTokenInfo(0, &info);
	p11->C_Login(session, login_type, (CK_UTF8CHAR *) pin, strlen(pin));
	fuzz_find_object(session, CKO_PRIVATE_KEY, &key, opt_id_len ? opt_id : NULL, opt_id_len);

	if (p11->C_SignInit(session, &mech, key) != CKR_OK)
		goto fin;
	p11->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR *) pin, strlen(pin));

	if (sign_data_size <= sizeof(in_buffer)) {
		memcpy(in_buffer, sign_data, sign_data_size);
		p11->C_Sign(session, in_buffer, sign_data_size, sig_buffer, &sig_len);
	} else {
		while (sign_data_size > 0) {
			to_process = sign_data_size < sizeof(in_buffer) ? sign_data_size : sizeof(in_buffer);
			sign_data_size -= to_process;
			memcpy(in_buffer, sign_data, to_process);
			sign_data += to_process;

			if (p11->C_SignUpdate(session, in_buffer, to_process) != CKR_OK)
				goto fin;
		}

		sig_len = sizeof(sig_buffer);
		p11->C_SignFinal(session, sig_buffer, &sig_len);
	}

fin:
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(pin);
}

static void test_verify(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE    session;
	CK_MECHANISM         mech = {0, NULL_PTR, 0};
	uint8_t              login_type = CKU_USER;
	char                *pin = NULL;
	const unsigned char *opt_id = NULL;
	size_t               opt_id_len = 0;
	const uint8_t       *verify_data = NULL, *sig_data = NULL;
	size_t               verify_data_size = 0;
	CK_OBJECT_HANDLE     key = CK_INVALID_HANDLE;
	unsigned char        in_buffer[1025], sig_buffer[512];
	CK_ULONG             sig_len = sizeof(sig_buffer);
	size_t               to_process = 0;

	/* Process options*/
	if (set_mechanism(&data, &size, &mech) || size < 3)
		return;
	login_type = data[0];
	data++; size--;
	if (!(pin = extract_word(&data, &size)))
		return;
	opt_id = data;
	opt_id_len = get_buffer(&opt_id, size, &data, &size, 256);

	/* Prepare buffer with data */
	verify_data = data;
	if ((verify_data_size = get_buffer(&verify_data, size, &data, &size, 6000)) == 0)
		goto end;
	/* Get buffer with signature */
	sig_data = data;
	if ((sig_len = get_buffer(&sig_data, size, &data, &size, 512)) == 0)
		goto end;
	memcpy(sig_buffer, sig_data, sig_len);

	/* Initialize */
	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;

	p11->C_Login(session, login_type, (CK_UTF8CHAR *) pin, strlen(pin));

	if (!fuzz_find_object(session, CKO_PUBLIC_KEY, &key, opt_id_len ? opt_id : NULL, opt_id_len)
		&& !fuzz_find_object(session, CKO_CERTIFICATE, &key, opt_id_len ? opt_id : NULL, opt_id_len))
		goto fin;

	if (p11->C_VerifyInit(session, &mech, key) != CKR_OK)
		goto fin;

	if (verify_data_size <= sizeof(in_buffer)) {
		memcpy(in_buffer, verify_data, verify_data_size);
		p11->C_Verify(session, in_buffer, verify_data_size, sig_buffer, sig_len);
	} else {
		while (verify_data_size > 0) {
			to_process = verify_data_size < sizeof(in_buffer) ? verify_data_size : sizeof(in_buffer);
			verify_data_size -= to_process;
			memcpy(in_buffer, verify_data, to_process);
			verify_data += to_process;

			if (p11->C_VerifyUpdate(session, in_buffer, to_process) != CKR_OK)
				goto fin;
		}

		p11->C_VerifyFinal(session, sig_buffer, sig_len);
	}
fin:
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(pin);
}

static void test_decrypt(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE    session;
	uint8_t              login_type = CKU_USER;
	char                *pin = NULL;
	const unsigned char *opt_id;
	size_t               opt_id_len = 0;
	const uint8_t       *dec_data = NULL;
	size_t               dec_data_size = 0;
	CK_OBJECT_HANDLE     key = CK_INVALID_HANDLE;
	unsigned char        in_buffer[1024], out_buffer[1024];
	CK_MECHANISM         mech = {0, NULL_PTR, 0};
	size_t               out_len = 0;

	/* Process options*/
	if (set_mechanism(&data, &size, &mech) || size < 3)
		return;
	login_type = data[0];
	data++; size--;
	if (!(pin = extract_word(&data, &size)))
		return;
	opt_id = data;
	opt_id_len = get_buffer(&opt_id, size, &data, &size, 256);

	/* Prepare buffer for signing */
	dec_data = data;
	if ((dec_data_size = get_buffer(&dec_data, size, &data, &size, 1024)) == 0)
		goto end;

	/* Initialize */
	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;

	p11->C_Login(session, login_type, (CK_UTF8CHAR *) pin, strlen(pin));
	if (!fuzz_find_object(session, CKO_PRIVATE_KEY, &key, opt_id_len ? opt_id : NULL, opt_id_len)
		&& !fuzz_find_object(session, CKO_SECRET_KEY, &key, opt_id_len ? opt_id : NULL, opt_id_len))
		goto fin;

	if (p11->C_DecryptInit(session, &mech, key) != CKR_OK)
		goto fin;

	p11->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR *) pin, strlen(pin));
	out_len = sizeof(out_buffer);

	memcpy(in_buffer, dec_data, dec_data_size);
	p11->C_Decrypt(session, in_buffer, dec_data_size, out_buffer, &out_len);
fin:
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(pin);
}

static void test_wrap(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE    session;
	uint8_t              login_type = CKU_USER;
	char                *pin = NULL;
	CK_BYTE              pWrappedKey[4096];
	CK_ULONG             pulWrappedKeyLen = sizeof(pWrappedKey);
	CK_MECHANISM         mech = {0, NULL_PTR, 0};
	CK_OBJECT_HANDLE     hWrappingKey;
	CK_OBJECT_HANDLE     hkey;
	const unsigned char *hkey_id;
	const unsigned char *opt_id;
	size_t               opt_id_len = 0, hkey_id_len = 0;

	/* Set options */
	if (set_mechanism(&data, &size, &mech) || size < 3)
		return;
	login_type = data[0];
	data++; size--;
	if (!(pin = extract_word(&data, &size)))
		return;
	opt_id = data;
	opt_id_len = get_buffer(&opt_id, size, &data, &size, 256);
	hkey_id = data;
	hkey_id_len = get_buffer(&hkey_id, size, &data, &size, 256);

	/* Initialize */
	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;

	p11->C_Login(session, login_type, (CK_UTF8CHAR *) pin, strlen(pin));
	if (!fuzz_find_object(session, CKO_SECRET_KEY, &hkey, hkey_id_len ? hkey_id : NULL, hkey_id_len))
		goto fin;
	if (!fuzz_find_object(session, CKO_PUBLIC_KEY, &hWrappingKey, opt_id_len ? opt_id : NULL, opt_id_len))
		if (!fuzz_find_object(session, CKO_SECRET_KEY, &hWrappingKey, opt_id_len ? opt_id : NULL, opt_id_len))
			goto fin;
	p11->C_WrapKey(session, &mech, hWrappingKey, hkey, pWrappedKey, &pulWrappedKeyLen);

fin:
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(pin);
}

#define FILL_ATTR(attr, typ, val, len) do { \
	(attr).type=(typ); \
	(attr).pValue=(val); \
	(attr).ulValueLen=len; \
} while(0)

void fill_bool_attr(CK_ATTRIBUTE **keyTemplate, int *n_attr, int type, int value)
{
	if (value) {
		FILL_ATTR((*keyTemplate)[*n_attr], type, &_true, sizeof(_true));
	}
	else {
		FILL_ATTR((*keyTemplate)[*n_attr], type, &_false, sizeof(_false));
	}
	
	++(*n_attr);
}

int fill_key_template(CK_ATTRIBUTE **keyTemplate, int *n_attr, const uint8_t **data, size_t *size, CK_OBJECT_CLASS *class, int token)
{
	const unsigned char *ptr = NULL;
	size_t               ecparams_size = 0;
	size_t               opt_object_label_size = 0;
	size_t               opt_object_id_len = 0;
	size_t               opt_allowed_mechanisms_len = 0;
	int bool_types[] = {CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, CKA_VERIFY, CKA_SENSITIVE,
						CKA_SIGN, CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP,
						CKA_DERIVE, CKA_PRIVATE, CKA_ALWAYS_AUTHENTICATE, CKA_EXTRACTABLE};

	if (!(*keyTemplate = malloc(20 * sizeof(CK_ATTRIBUTE))))
		return 1;
	memset(*keyTemplate, 0, 20 * sizeof(CK_ATTRIBUTE));
	FILL_ATTR((*keyTemplate)[0], CKA_CLASS, class, sizeof(CKA_CLASS));
	*n_attr = 1;
	fill_bool_attr(keyTemplate, n_attr, CKA_TOKEN, token);

	for (int i = 0; i < 13; i++) {
		/* ... | present -> 0/1 | value | ...*/
		if (*size < 3)
			return 1;
		if ((*data)[0] % 2) {
			fill_bool_attr(keyTemplate, n_attr, bool_types[i], (*data)[1] % 2);
			(*data)++; (*size)--;
		}
		(*data)++; (*size)--;
	}

	if (*size > 2 && (*data)[0] % 2 && *n_attr < 20){
		/* ... | present -> 0/1 | value | ...*/
		key_type = (CK_ULONG) (*data)[1];
		FILL_ATTR((*keyTemplate)[*n_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
		++(*n_attr);
		(*data) += 2;
		(*size) -= 2;
	}

	if (*size > 3 && (*data)[0] % 2 && *n_attr < 20){
		/* ... | present -> 0/1 | len | len | data | ... */
		(*data)++; (*size)--;
		ptr = *data;
		if ((ecparams_size = get_buffer(&ptr, *size, data, size, 256)) == 0)
			return 1;
		memcpy(ecparams, ptr, ecparams_size);
		FILL_ATTR((*keyTemplate)[*n_attr], CKA_EC_PARAMS, ecparams, ecparams_size);
		++(*n_attr);
	}

	if (*size > 3 && (*data)[0] % 2 && *n_attr < 20){
		/* ... | present -> 0/1 | len | len | data | ... */
		(*data)++; (*size)--;
		ptr = *data;
		if ((opt_object_label_size = get_buffer(&ptr, *size, data, size, 128)) == 0)
			return 1;
		memcpy(opt_object_label, ptr, opt_object_label_size);
		FILL_ATTR((*keyTemplate)[*n_attr], CKA_LABEL, opt_object_label, opt_object_label_size);
		++(*n_attr);
	}

	if (*size > 3 && (*data)[0] % 2 && *n_attr < 20){
		/* ... | present -> 0/1 | len | len | data | ... */
		(*data)++; (*size)--;
		ptr = *data;
		if ((opt_object_id_len = get_buffer(&ptr, *size, data, size, 100)) == 0)
			return 1;
		memcpy(opt_object_id, ptr, opt_object_id_len);
		FILL_ATTR((*keyTemplate)[*n_attr], CKA_ID, opt_object_id, opt_object_id_len);
		++(*n_attr);
	}
	if (*size > 4 && (*data)[0]  % 2 && *n_attr < 20){
		/* ... | present -> 0/1 | len | mech1 | mech2 | ... | mechn | ... */
		opt_allowed_mechanisms_len = (*data)[1] > 20 ? 20 : (*data)[1];
		(*data) += 2;
		(*size) -= 2;
		for (size_t i = 0; i < opt_allowed_mechanisms_len; i++) {
			if (*size <= sizeof(unsigned int))
				return 1;
			opt_allowed_mechanisms[i] = *((unsigned int *)data);
			(*data) += sizeof(unsigned int);
			(*size) -= sizeof(unsigned int);
		}
		FILL_ATTR((*keyTemplate)[*n_attr], CKA_ALLOWED_MECHANISMS, opt_allowed_mechanisms, opt_allowed_mechanisms_len);
		++(*n_attr);
	}
	if (*size == 0)
		return 1;
	return 0;
}

static void test_unwrap(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE    session;
	CK_MECHANISM         mech = {0, NULL_PTR, 0};
	uint8_t              login_type = CKU_USER;
	char                *pin = NULL;
	const unsigned char *opt_id, *wrapped_key;
	size_t               opt_id_len;
	CK_OBJECT_HANDLE     hUnwrappingKey;
	CK_ULONG             wrapped_key_length;
	CK_BYTE_PTR          pWrappedKey;
	unsigned char        in_buffer[1024];
	CK_OBJECT_CLASS      secret_key_class = CKO_SECRET_KEY;
	CK_ATTRIBUTE        *keyTemplate = NULL;
	int                  n_attr = 2;
	CK_OBJECT_HANDLE     hSecretKey;

	/* Set options */
	if (set_mechanism(&data, &size, &mech) || size < 3)
		goto end;
	login_type = data[0];
	data++; size--;
	if (!(pin = extract_word(&data, &size)))
		goto end;
	opt_id = data;
	opt_id_len = get_buffer(&opt_id, size, &data, &size, 256);
	wrapped_key = data;
	if ((wrapped_key_length = get_buffer(&wrapped_key, size, &data, &size, 1024)) == 0)
		goto end;
	memcpy(in_buffer, wrapped_key, wrapped_key_length);
	pWrappedKey = in_buffer;

	if (fill_key_template((CK_ATTRIBUTE **) &keyTemplate, &n_attr, &data, &size, &secret_key_class, true))
		goto end;

	/* Initialize */
	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;

	p11->C_Login(session, login_type, (CK_UTF8CHAR *) pin, strlen(pin));
	/* Find keys*/
	if (!fuzz_find_object(session, CKO_PRIVATE_KEY, &hUnwrappingKey, opt_id_len ? opt_id : NULL, opt_id_len))
		if (!fuzz_find_object(session, CKO_SECRET_KEY, &hUnwrappingKey, opt_id_len ? opt_id : NULL, opt_id_len))
			goto fin;
	p11->C_UnwrapKey(session, &mech, hUnwrappingKey, pWrappedKey, wrapped_key_length, keyTemplate, n_attr, &hSecretKey);

fin:
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(pin);
	free(keyTemplate);
}

static void test_derive(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE    session;
	CK_OBJECT_HANDLE     key;
	CK_MECHANISM         mech = {0, NULL_PTR, 0};
	uint8_t              login_type = CKU_USER;
	char                *pin = NULL;
	const unsigned char *opt_id = NULL;
	size_t               opt_id_len;
	CK_OBJECT_HANDLE     newkey = 0;
	CK_OBJECT_CLASS      newkey_class = CKO_SECRET_KEY;
	CK_ATTRIBUTE        *keyTemplate = NULL;
	int                  n_attrs = 2;

	/* Set options */
	if (set_mechanism(&data, &size, &mech) || size < 3)
		goto end;
	login_type = data[0];
	data++; size--;
	if (!(pin = extract_word(&data, &size)))
		goto end;
	opt_id = data;
	opt_id_len = get_buffer(&opt_id, size, &data, &size, 256);
	if (fill_key_template((CK_ATTRIBUTE **) &keyTemplate, &n_attrs, &data, &size, &newkey_class, false))
		goto end;

	/* Initialize */
	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;

	p11->C_Login(session, login_type, (CK_UTF8CHAR *) pin, strlen(pin));
	if (fuzz_find_object(session, CKO_PRIVATE_KEY, &key, opt_id_len ? opt_id : NULL, opt_id_len))
		p11->C_DeriveKey(session, &mech, key, keyTemplate, n_attrs, &newkey);

	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(pin);
	free(keyTemplate);
}

static void test_genkeypair(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE  hPublicKey;
	CK_OBJECT_HANDLE  hPrivateKey;
	CK_MECHANISM      mech = {0, NULL_PTR, 0};
	uint8_t           login_type = CKU_USER;
	char             *pin = NULL;
	CK_OBJECT_CLASS   pubkey_class = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS   privkey_class = CKO_PRIVATE_KEY;
	int               n_pubkey_attr = 2;
	int               n_privkey_attr = 2;
	CK_ATTRIBUTE     *publicKeyTemplate = NULL;
	CK_ATTRIBUTE     *privateKeyTemplate = NULL;

	/* Process options*/
	if (set_mechanism(&data, &size, &mech) || size < 3)
		goto end;
	login_type = data[0];
	data++; size--;
	if (!(pin = extract_word(&data, &size)))
		goto end;

	if (fill_key_template(&publicKeyTemplate, &n_pubkey_attr, &data, &size, &pubkey_class, true) != 0
		|| fill_key_template(&privateKeyTemplate, &n_privkey_attr, &data, &size, &privkey_class, true) != 0)
		goto end;

	/* Initialize */
	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;

	p11->C_Login(session, login_type, (CK_UTF8CHAR *) pin, strlen(pin));
	p11->C_GenerateKeyPair(session, &mech, publicKeyTemplate, n_pubkey_attr,
						   privateKeyTemplate, n_privkey_attr,
						   &hPublicKey, &hPrivateKey);
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);

end:
	free(pin);
	free(privateKeyTemplate);
	free(publicKeyTemplate);
}

static void test_store_data(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE  data_obj;
	CK_OBJECT_CLASS   class = CKO_DATA;
	uint8_t           login_type = CKU_USER;
	unsigned char     contents[5001];
	int               contents_len = 0;
	const uint8_t    *ptr = NULL;
	CK_ATTRIBUTE     *data_templ = NULL;
	int               n_data_attr = 0;
	char             *pin = NULL;
	unsigned char     app_id[256];
	int               app_id_len = 0;

	/* Create data template */
	if (!(data_templ = malloc(20 * sizeof(CK_ATTRIBUTE))))
		return;
	memset(data_templ, 0, 20 * sizeof(CK_ATTRIBUTE));

	/* Get PIN */
	if (!(pin = extract_word(&data, &size)))
		goto end;

	/* Extract content from fuzzing input*/
	memset(contents, 0, sizeof(contents));
	ptr = data;
	if ((contents_len = get_buffer(&ptr, size, &data, &size, 5000)) == 0)	
		goto end;
	memcpy(contents, ptr, contents_len);
	contents[contents_len] = '\0';

	/* Fill attributes to data template */
	if (size < 4)
		goto end;
	FILL_ATTR(data_templ[n_data_attr], CKA_CLASS, &class, sizeof(class));
	n_data_attr++;
	FILL_ATTR(data_templ[n_data_attr], CKA_VALUE, &contents, contents_len);
	n_data_attr++;
	fill_bool_attr(&data_templ, &n_data_attr, CKA_TOKEN, *data % 2);
	data++; size--;
	fill_bool_attr(&data_templ, &n_data_attr, CKA_PRIVATE, *data % 2);
	data++; size--;

	/* Get application id*/
	if (data[0] % 2){
		data++; size--;
		ptr = data;
		if ((app_id_len = get_buffer(&ptr, size, &data, &size, 256)) == 0)
			goto end;
		memcpy(app_id, ptr, app_id_len);
		FILL_ATTR(data_templ[n_data_attr], CKA_OBJECT_ID, app_id, app_id_len);
		n_data_attr++;
	}

	/* Initialize */
	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;

	p11->C_Login(session, login_type, (CK_UTF8CHAR *) pin, strlen(pin));
	p11->C_CreateObject(session, data_templ, n_data_attr, &data_obj);
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(data_templ);
	free(pin);
}

static void test_store_cert(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE   session;
	CK_OBJECT_CLASS     class = CKO_CERTIFICATE;
	uint8_t             login_type = CKU_USER;
	unsigned char       contents[5000];
	int                 contents_len = 0;
	const uint8_t      *ptr = NULL;
	CK_ATTRIBUTE       *cert_templ = NULL;
	int                 n_cert_attr = 0;
	char               *pin = NULL;
	CK_OBJECT_HANDLE    cert_obj;
	CK_CERTIFICATE_TYPE cert_type = CKC_X_509;

	/* Create certificate template */
	if (!(cert_templ = malloc(20 * sizeof(CK_ATTRIBUTE))))
		return;
	memset(cert_templ, 0, 20 * sizeof(CK_ATTRIBUTE));

	/* Get PIN */
	if (!(pin = extract_word(&data, &size)))
		goto end;

	/* Extract content from fuzzing input */
	memset(contents, 0, sizeof(contents));
	ptr = data;
	if ((contents_len = get_buffer(&ptr, size, &data, &size, 5000)) == 0)	
		goto end;
	memcpy(contents, ptr, contents_len);
	contents[contents_len] = '\0';

	/* Fill attributes to certificate template */
	if (size < 4)
		goto end;
	FILL_ATTR(cert_templ[n_cert_attr], CKA_CLASS, &class, sizeof(class));
	n_cert_attr++;
	FILL_ATTR(cert_templ[n_cert_attr], CKA_VALUE, contents, contents_len);
	n_cert_attr++;
	FILL_ATTR(cert_templ[n_cert_attr], CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type));
	n_cert_attr++;
	fill_bool_attr(&cert_templ, &n_cert_attr, CKA_TOKEN, *data % 2);
	data++; size--;
	fill_bool_attr(&cert_templ, &n_cert_attr, CKA_PRIVATE, *data % 2);
	data++; size--;

	/* Initialize */
	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;

	p11->C_Login(session, login_type, (CK_UTF8CHAR *) pin, strlen(pin));
	p11->C_CreateObject(session, cert_templ, n_cert_attr, &cert_obj);
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(pin);
	free(cert_templ);
}

static void test_store_key(const uint8_t *data, size_t size)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_CLASS   class = CKO_SECRET_KEY;
	uint8_t           login_type = CKU_USER;
	unsigned char     contents[5000];
	int               contents_len = 0;
	const uint8_t    *ptr = NULL;
	CK_ATTRIBUTE     *key_template = NULL;
	int               n_key_attr = 0;
	char             *pin = NULL;
	CK_OBJECT_HANDLE  key_obj;

	memset(contents, 0, sizeof(contents));
	if (size < 3)
		return;
	class = *data;
	data++; size--;

	/* Get PIN */
	if (!(pin = extract_word(&data, &size)))
		goto end;

	if (fill_key_template(&key_template, &n_key_attr, &data, &size, &class, true) != 0)
		goto end;

	if (size < 3)
		goto end;
	if (data[0] && n_key_attr < 20) {
		data++; size--;
		ptr = data;
		if ((contents_len = get_buffer(&ptr, size, &data, &size, 5000)) == 0)	
			goto end;
		memcpy(contents, ptr, contents_len);
		FILL_ATTR(key_template[n_key_attr], CKA_VALUE, contents, contents_len);
		n_key_attr++;
	}

	/* Initialize */
	if (fuzz_pkcs11_initialize(data, size, NULL, &session) != CKR_OK)
		goto end;

	p11->C_Login(session, login_type, (CK_UTF8CHAR *) pin, strlen(pin));
	p11->C_CreateObject(session, key_template, n_key_attr, &key_obj);
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL);
end:
	free(pin);
	free(key_template);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t operation = 0;
	void (*func_ptr[])(const uint8_t*, size_t) = {
		test_change_pin,
		test_init_pin,
		test_init_token,
		test_random,
		test_digest_update,
		test_digest,
		test_sign,
		test_verify,
		test_decrypt,
		test_wrap,
		test_unwrap,
		test_derive,
		test_genkeypair,
		test_store_data,
		test_store_cert,
		test_store_key
	};

	if (size < 10)
		return 0;

	operation = *data % 16;
	data++;
	size--;

	func_ptr[operation](data, size);

	return 0;
}
