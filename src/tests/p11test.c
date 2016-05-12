#include "p11test_helpers.h"
#include "p11test_common.h"
#include <getopt.h>

int encrypt_decrypt_test(test_cert_t *o, token_info_t *info, test_mech_t *mech)
{
	CK_RV rv;
	CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE *message = (CK_BYTE *)SHORT_MESSAGE_TO_SIGN;
	CK_ULONG message_length = strlen((char*) message);
	CK_BYTE dec_message[BUFFER_SIZE];
	CK_ULONG dec_message_length = BUFFER_SIZE;
	unsigned char *enc_message;
	int enc_message_length;

	sign_mechanism.mechanism = mech->mech;
	if (o->type != EVP_PK_RSA) {
		debug_print(" [ KEY %s ] Skip non-RSA key for encryption", o->id_str);
		return 0;
	}

	debug_print(" [ KEY %s ] Encrypt message", o->id_str);
	enc_message = malloc(RSA_size(o->key.rsa));
	if (enc_message == NULL)
		fail_msg("malloc returned null");

	enc_message_length = RSA_public_encrypt(message_length, message,
		enc_message, o->key.rsa, RSA_PKCS1_PADDING);
	if (enc_message_length < 0) {
		free(enc_message);
		fail_msg("RSA_public_encrypt: rv = 0x%.8X\n", enc_message_length);
	}

	debug_print(" [ KEY %s ] Decrypt message", o->id_str);
	rv = info->function_pointer->C_DecryptInit(info->session_handle, &sign_mechanism,
		o->private_handle);
	if (rv == CKR_KEY_TYPE_INCONSISTENT) {
		debug_print(" [ SKIP %s ] Not allowed to decrypt with this key?", o->id_str);
		free(enc_message);
		return 0;
	}
	if (rv != CKR_OK)
		fail_msg("C_DecryptInit: rv = 0x%.8X\n", rv);

	rv = info->function_pointer->C_Decrypt(info->session_handle, enc_message,
		enc_message_length, dec_message, &dec_message_length);
	free(enc_message);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		debug_print(" [ SKIP %s ] Not allowed to decrypt with this key?", o->id_str);
		return 0;
	} else if (rv != CKR_OK)
		fail_msg("C_Decrypt: rv = 0x%.8X\n", rv);

	dec_message[dec_message_length] = '\0';
	if (memcmp(dec_message, message, dec_message_length) == 0
			&& dec_message_length == message_length) {
		debug_print(" [ OK %s ] Text decrypted successfully.", o->id_str);
		mech->flags |= VERIFY_DECRYPT;
	} else {
		debug_print(" [ ERROR %s ] Text decryption failed. Recovered text: %s",
			o->id_str, dec_message);
		return 0;
	}
	return 1;
}

int sign_verify_test(test_cert_t *o, token_info_t *info, test_mech_t *mech,
	CK_ULONG message_length)
{
	CK_RV rv;
	CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE *message = (CK_BYTE *)SHORT_MESSAGE_TO_SIGN;
	CK_BYTE *sign = NULL;
	CK_ULONG sign_length = 0;
	unsigned int nlen;
	int dec_message_length;

	if (message_length > strlen((char *)message))
		fail_msg("Truncate is longer than the actual message");

	sign_mechanism.mechanism = mech->mech;
	if (o->type != EVP_PK_EC && o->type != EVP_PK_RSA) {
		debug_print(" [ KEY %s ] Skip non-RSA and non-EC key", o->id_str);
		return 0;
	}

	debug_print(" [ KEY %s ] Signing message of length %d", o->id_str, message_length);

	rv = info->function_pointer->C_SignInit(info->session_handle, &sign_mechanism,
		o->private_handle);
	if (rv == CKR_KEY_TYPE_INCONSISTENT) {
		debug_print(" [ SKIP %s ] Not allowed to sign with this key?", o->id_str);
		return 0;
	} else if (rv == CKR_MECHANISM_INVALID) {
		debug_print(" [ SKIP %s ] Bad mechanism. Not supported?", o->id_str);
		return 0;
	} else if (rv != CKR_OK)
		fail_msg("C_SignInit: rv = 0x%.8X\n", rv);

	if (o->always_auth) {
		rv = info->function_pointer->C_Login(info->session_handle,
			CKU_CONTEXT_SPECIFIC, card_info.pin, card_info.pin_length);
		if (rv != CKR_OK) {
			debug_print(" [ SKIP %s ] Re-authentication failed", o->id_str);
		}
	}

	/* Call C_Sign with NULL argument to find out the real size of signature */
	rv = info->function_pointer->C_Sign(info->session_handle,
		message, message_length, sign, &sign_length);
	if (rv != CKR_OK)
		fail_msg("C_Sign: rv = 0x%.8X\n", rv);

	sign = malloc(sign_length);
	if (sign == NULL)
		fail_msg("malloc failed");

	/* Call C_Sign with allocated buffer to the the actual signature */
	rv = info->function_pointer->C_Sign(info->session_handle,
		message, message_length, sign, &sign_length);
	if (rv != CKR_OK) {
		free(sign);
		fail_msg("C_Sign: rv = 0x%.8X\n", rv);
	}

	debug_print(" [ KEY %s ] Verify message sinature", o->id_str);
	dec_message_length = 0;
	if (o->type == EVP_PK_RSA) {
		CK_BYTE dec_message[BUFFER_SIZE];
		dec_message_length = RSA_public_decrypt(sign_length, sign,
			dec_message, o->key.rsa, RSA_PKCS1_PADDING);
		free(sign);
		if (dec_message_length < 0)
			fail_msg("RSA_public_decrypt: rv = %d: %s\n", dec_message_length,
				ERR_error_string(ERR_peek_last_error(), NULL));
		dec_message[dec_message_length] = '\0';
		if (memcmp(dec_message, message, dec_message_length) == 0
				&& dec_message_length == (int) message_length) {
			debug_print(" [ OK %s ] Signature is valid.", o->id_str);
			mech->flags |= VERIFY_SIGN;
		 } else {
			debug_print(" [ ERROR %s ] Signature is not valid. Recovered text: %s",
				o->id_str, dec_message);
			return 0;
		}
	} else if (o->type == EVP_PK_EC) {
		ECDSA_SIG *sig = ECDSA_SIG_new();
		if (sig == NULL)
			fail_msg("ECDSA_SIG_new: failed");
		nlen = sign_length/2;
		BN_bin2bn(&sign[0], nlen, sig->r);
		BN_bin2bn(&sign[nlen], nlen, sig->s);
		free(sign);
		if ((rv = ECDSA_do_verify(message, message_length, sig, o->key.ec)) == 1) {
			debug_print(" [ OK %s ] EC Signature of length %d is valid.",
				o->id_str, message_length);
			mech->flags |= VERIFY_SIGN;
		} else {
			fail_msg("ECDSA_do_verify: rv = %d: %s\n", rv,
				ERR_error_string(ERR_peek_last_error(), NULL));
		}
		ECDSA_SIG_free(sig);
	} else {
		debug_print(" [ KEY %s ] Unknown type. Not verifying", o->id_str);
		return 0;
	}

	return 1;
}

int search_objects(test_certs_t *objects, token_info_t *info,
	CK_ATTRIBUTE filter[], CK_LONG filter_size, CK_ATTRIBUTE template[], CK_LONG template_size,
	int (*callback)(test_certs_t *, CK_ATTRIBUTE[], unsigned int, CK_OBJECT_HANDLE))
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_ULONG object_count;
	CK_OBJECT_HANDLE object_handle = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE_PTR object_handles = NULL;
	unsigned long i = 0, objects_length = 0;

	/* FindObjects first
	 * https://wiki.oasis-open.org/pkcs11/CommonBugs
	 */
	rv = fp->C_FindObjectsInit(info->session_handle, filter, filter_size);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_FindObjectsInit: rv = 0x%.8lX\n", rv);
		return -1;
	}

	while(1) {
		rv = fp->C_FindObjects(info->session_handle, &object_handle, 1, &object_count);
		if (object_count == 0)
			break;
		if (rv != CKR_OK) {
			fprintf(stderr, "C_FindObjects: rv = 0x%.8lX\n", rv);
			return -1;
		}
		/* store handle */
		if (i >= objects_length) {
			objects_length += 4; // do not realloc after each row
			object_handles = realloc(object_handles, objects_length * sizeof(CK_OBJECT_HANDLE_PTR));
			if (object_handles == NULL)
		 		fail_msg("Realloc failed. Need to store object handles.\n");
		}
		object_handles[i++] = object_handle;
	}
	objects_length = i; //terminate list of handles

	rv = fp->C_FindObjectsFinal(info->session_handle);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_FindObjectsFinal: rv = 0x%.8lX\n", rv);
 		fail_msg("Could not find certificate.\n");
	}

	for (i = 0;i < objects_length; i++) {
		/* Find attributes one after another to handle errors
		 * https://wiki.oasis-open.org/pkcs11/CommonBugs
		 */
		for (int j = 0; j < template_size; j++) {
			template[j].pValue = NULL;
			template[j].ulValueLen = 0;

			rv = fp->C_GetAttributeValue(info->session_handle, object_handles[i],
				&(template[j]), 1);
			if (rv == CKR_ATTRIBUTE_TYPE_INVALID)
				continue;
			else if (rv != CKR_OK)
				fail_msg("C_GetAttributeValue: rv = 0x%.8X\n", rv);

			/* Allocate memory to hold the data we want */
			if (template[j].ulValueLen != 0) {
				template[j].pValue = malloc(template[j].ulValueLen);
				if (template[j].pValue == NULL)
					fail_msg("malloc failed");
			}
			/* Call again to get actual attribute */
			rv = fp->C_GetAttributeValue(info->session_handle, object_handles[i],
				&(template[j]), 1);
			if (rv != CKR_OK)
				fail_msg("C_GetAttributeValue: rv = 0x%.8X\n", rv);
		}

		callback(objects, template, template_size, object_handles[i]);
		// XXX check results
		for (int j = 0; j < template_size; j++)
			free(template[j].pValue);
	}
	free(object_handles);
	return 0;
}

/**
 * Allocate place in the structure for every certificte found
 * and store related information
 */
int callback_certificates(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned int template_size, CK_OBJECT_HANDLE object_handle)
{
	EVP_PKEY *evp = NULL;
	const u_char *cp;
	test_cert_t *o = NULL;

	objects->count = objects->count+1;
	objects->data = realloc(objects->data, objects->count*sizeof(test_cert_t));
	if (objects->data == NULL)
		return -1;

	o = &(objects->data[objects->count - 1]);

	/* get the type and data, store in some structure */
	o->key_id = malloc(template[0].ulValueLen);
	o->key_id = memcpy(o->key_id, template[0].pValue, template[0].ulValueLen);
	o->key_id_size = template[0].ulValueLen;
	o->id_str = convert_byte_string(o->key_id, o->key_id_size);
	o->private_handle = CK_INVALID_HANDLE;
	o->always_auth = 0;
	o->bits = 0;
	o->label = malloc(template[2].ulValueLen + 1);
	strncpy(o->label, template[2].pValue, template[2].ulValueLen);
	o->label[template[2].ulValueLen] = '\0';
	o->verify_public = 0;
	o->mechs = NULL;
	o->type = -1;
	cp = template[1].pValue;
	if ((o->x509 = X509_new()) == NULL) {
		fail_msg("X509_new");
	} else if (d2i_X509(&(o->x509), (const unsigned char **) &cp,
			template[1].ulValueLen) == NULL) {
		fail_msg("d2i_X509");
	} else if ((evp = X509_get_pubkey(o->x509)) == NULL) {
		fail_msg("X509_get_pubkey failed.");
	}
	if (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		if ((o->key.rsa = RSAPublicKey_dup(evp->pkey.rsa)) == NULL)
			fail_msg("RSAPublicKey_dup failed");
		o->type = EVP_PK_RSA;
		o->bits = EVP_PKEY_bits(evp);

		o->num_mechs = 1; // the only mechanism for RSA
		o->mechs = malloc(sizeof(test_mech_t));
		if (o->mechs == NULL)
			fail_msg("malloc failed for mechs");
		o->mechs[0].mech = CKM_RSA_PKCS;
		o->mechs[0].flags = 0;
	} else if (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		if ((o->key.ec = EC_KEY_dup(evp->pkey.ec)) == NULL)
			fail_msg("EC_KEY_dup failed");
		o->type = EVP_PK_EC;
		o->bits = EVP_PKEY_bits(evp);

		o->num_mechs = 1; // XXX CKM_ECDSA_SHA1 is not supported on Test PIV cards
		o->mechs = malloc(2*sizeof(test_mech_t));
		if (o->mechs == NULL)
			fail_msg("malloc failed for mechs");
		o->mechs[0].mech = CKM_ECDSA;
		o->mechs[0].flags = 0;
		o->mechs[1].mech = CKM_ECDSA_SHA1;
		o->mechs[1].flags = 0;
	} else {
		debug_print("[ WARN %s ]evp->type = 0x%.4X (not RSA, EC)\n", o->id_str, evp->type);
	}
	EVP_PKEY_free(evp);

	debug_print(" [ OK %s ] Certificate with label %s loaded successfully",
		o->id_str, o->label);
	return 1;
}

/**
 * Pair found private keys on the card with existing certificates
 */
int callback_private_keys(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned int template_size, CK_OBJECT_HANDLE object_handle)
{
	unsigned int i = 0;
	char *key_id = convert_byte_string(template[3].pValue, template[3].ulValueLen);
	while (i < objects->count && objects->data[i].key_id_size == template[3].ulValueLen && 
		memcmp(objects->data[i].key_id, template[3].pValue, template[3].ulValueLen) != 0)
		i++;

	if (i == objects->count) {
		fprintf(stderr, "Can't find certificate for private key with ID %s\n", key_id);
		free(key_id);
		return -1;
	}
	if (objects->data[i].private_handle != CK_INVALID_HANDLE) {
		fprintf(stderr, "Object already filled? ID %s\n", key_id);
		free(key_id);
		return -1;
	}
	free(key_id);

	objects->data[i].private_handle = object_handle;
	objects->data[i].sign = (template[0].ulValueLen != (CK_BBOOL) -1)
		? *((CK_BBOOL *) template[0].pValue) : CK_FALSE;
	objects->data[i].decrypt = (template[1].ulValueLen != (CK_BBOOL) -1)
		? *((CK_BBOOL *) template[1].pValue) : CK_FALSE;
	objects->data[i].key_type = (template[2].ulValueLen != (CK_ULONG) -1)
		? *((CK_KEY_TYPE *) template[2].pValue) : (CK_KEY_TYPE) -1;
	objects->data[i].always_auth = (template[2].ulValueLen != (CK_BBOOL) -1)
		? *((CK_BBOOL *) template[2].pValue) : CK_FALSE;

	debug_print(" [ OK %s ] Private key to the certificate found successfully S:%d D:%d T:%02X",
		objects->data[i].id_str, objects->data[i].sign, objects->data[i].decrypt,
		objects->data[i].key_type);
	return 0;
}

/**
 * Pair found public keys on the card with existing certificates
 */
int callback_public_keys(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned int template_size, CK_OBJECT_HANDLE object_handle)
{
	unsigned int i = 0;
	char *key_id = convert_byte_string(template[3].pValue, template[3].ulValueLen);
	while (i < objects->count && objects->data[i].key_id_size == template[3].ulValueLen && 
		memcmp(objects->data[i].key_id, template[3].pValue, template[3].ulValueLen) != 0)
		i++;

	if (i == objects->count) {
		fprintf(stderr, "Can't find certificate for public key with ID %s\n", key_id);
		free(key_id);
		return -1;
	}
	if (objects->data[i].verify_public != 0) {
		fprintf(stderr, "Object already filled? ID %s\n", key_id);
		free(key_id);
		return -1;
	}
	free(key_id);

	objects->data[i].verify = (template[0].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[0].pValue) : CK_FALSE;
	objects->data[i].encrypt = (template[1].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[1].pValue) : CK_FALSE;

	/* check if we get the same public key as from the certificate */
	if (objects->data[i].key_type == CKK_RSA) {
		RSA *rsa = RSA_new();
		objects->data[i].bits = (template[6].ulValueLen != (CK_ULONG) -1)
			? *((CK_ULONG *)template[6].pValue) : 0;
		rsa->n = BN_bin2bn(template[4].pValue, template[4].ulValueLen, NULL);
		rsa->e = BN_bin2bn(template[5].pValue, template[5].ulValueLen, NULL);
		if (BN_cmp(objects->data[i].key.rsa->n, rsa->n) != 0 ||
			BN_cmp(objects->data[i].key.rsa->e, rsa->e) != 0) {
			debug_print(" [ WARN %s ] Got different public key then the from the certificate ID\n",
				objects->data[i].id_str);
			return -1;
		}
		RSA_free(rsa);
		objects->data[i].verify_public = 1;
	} else if (objects->data[i].key_type == CKK_EC) {
		debug_print(" [ WARN %s] EC public key check skipped so far\n",
			objects->data[i].id_str);

		//EC_KEY *ec = EC_KEY_new();
		//int nid = NID_X9_62_prime256v1; /* 0x11 */
		//int nid = NID_secp384r1;		/* 0x14 */
		//EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(nid);
		//EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);
		//EC_POINT *ecpoint = EC_POINT_new(ecgroup);

		//EC_KEY_set_public_key(ec, ecpoint);
		return -1;
	} else {
		debug_print(" [ WARN %s] non-RSA, non-EC key\n", objects->data[i].id_str);
		return -1;
	}

	debug_print(" [ OK %s ] Public key to the certificate found successfully V:%d E:%d T:%02X",
		objects->data[i].id_str, objects->data[i].verify, objects->data[i].encrypt,
		objects->data[i].key_type);
	return 0;
}

static void search_for_all_objects(test_certs_t *objects, token_info_t *info) {
	CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
	CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE filter[] = {
			{CKA_CLASS, &keyClass, sizeof(keyClass)},
	};
	CK_ATTRIBUTE attrs[] = {
			{ CKA_ID, NULL_PTR, 0},
			{ CKA_VALUE, NULL_PTR, 0},
			{ CKA_LABEL, NULL_PTR, 0},
			{ CKA_CERTIFICATE_TYPE, NULL_PTR, 0},

			/* Specific X.509 certificate attributes */
			//{ CKA_SUBJECT, NULL_PTR, 0},
			//{ CKA_ISSUER, NULL_PTR, 0},
			//{ CKA_SERIAL_NUMBER, NULL_PTR, 0},
			//{ CKA_ALLOWED_MECHANISMS, NULL_PTR, 0},
	};
	CK_ULONG attrs_size = sizeof (attrs) / sizeof (CK_ATTRIBUTE);
	CK_ATTRIBUTE private_attrs[] = {
			{ CKA_SIGN, NULL, 0}, // CK_BBOOL
			{ CKA_DECRYPT, NULL, 0}, // CK_BBOOL
			{ CKA_KEY_TYPE, NULL, 0}, // CKK_
			{ CKA_ID, NULL, 0},
			{ CKA_ALWAYS_AUTHENTICATE, NULL, 0}, // CK_BBOOL
	};
	CK_ULONG private_attrs_size = sizeof (private_attrs) / sizeof (CK_ATTRIBUTE);
	CK_ATTRIBUTE public_attrs[] = {
			{ CKA_VERIFY, NULL, 0}, // CK_BBOOL
			{ CKA_ENCRYPT, NULL, 0}, // CK_BBOOL
			{ CKA_KEY_TYPE, NULL, 0},
			{ CKA_ID, NULL, 0},
			{ CKA_MODULUS, NULL, 0},
			{ CKA_PUBLIC_EXPONENT, NULL, 0},
			{ CKA_MODULUS_BITS, NULL, 0},
			{ CKA_EC_PARAMS, NULL, 0},
			{ CKA_EC_POINT, NULL, 0},
	};
	CK_ULONG public_attrs_size = sizeof (public_attrs) / sizeof (CK_ATTRIBUTE);

	debug_print("\nSearch for all certificates on the card");
	search_objects(objects, info, filter, 1, // XXX size = 1
		attrs, attrs_size, callback_certificates);


	/* do the same thing with private keys (collect handles based on the collected IDs) */
	debug_print("\nSearch for all private keys respective to the certificates");
	filter[0].pValue = &privateClass;
	// search for all and pair on the fly
	search_objects(objects, info, filter, 1,
		private_attrs, private_attrs_size, callback_private_keys);

	debug_print("\nSearch for all public keys respective to the certificates");
	filter[0].pValue = &publicClass;
	search_objects(objects, info, filter, 1,
		public_attrs, public_attrs_size, callback_public_keys);
}

static void clean_all_objects(test_certs_t *objects) {
	unsigned int i;
	for (i = 0; i < objects->count; i++) {
		free(objects->data[i].key_id);
		free(objects->data[i].id_str);
		free(objects->data[i].label);
		free(objects->data[i].mechs);
		X509_free(objects->data[i].x509);
		if (objects->data[i].key_type == CKK_RSA)
			RSA_free(objects->data[i].key.rsa);
		else
			EC_KEY_free(objects->data[i].key.ec);
	}
	free(objects->data);
}

static void readonly_tests(void **state) {

	token_info_t *info = (token_info_t *) *state;
	unsigned int i;
	int used;
	test_certs_t objects;

	objects.count = 0;
	objects.data = NULL;

	search_for_all_objects(&objects, info);

	debug_print("\nCheck functionality of Sign&Verify and/or Encrypt&Decrypt");
	for (i = 0; i < objects.count; i++) {
		used = 0;
		/* do the Sign&Verify and/or Encrypt&Decrypt */
		/* XXX some keys do not have appropriate flags, but we can use them
		 * or vice versa */
		//if (objects.data[i].sign && objects.data[i].verify)
			for (int j = 0; j < objects.data[i].num_mechs; j++)
				used |= sign_verify_test(&(objects.data[i]), info,
					&(objects.data[i].mechs[j]), 32);

		//if (objects.data[i].encrypt && objects.data[i].decrypt)
			for (int j = 0; j < objects.data[i].num_mechs; j++)
				used |= encrypt_decrypt_test(&(objects.data[i]), info,
					&(objects.data[i].mechs[j]));

		if (!used) {
			debug_print(" [ WARN %s ] Private key with unknown purpose T:%02X",
			objects.data[i].id_str, objects.data[i].key_type);
		}
	}

	/* print summary */
	printf("[KEY ID] [TYPE] [SIZE] [PUBLIC] [SIGN&VERIFY] [ENC&DECRYPT] [LABEL]\n");
	for (i = 0; i < objects.count; i++) {
		printf("[%-6s] [%s] [%4lu] [ %s ] [%s%s] [%s%s] [%s]\n",
			objects.data[i].id_str,
			objects.data[i].key_type == CKK_RSA ? "RSA " :
				objects.data[i].key_type == CKK_EC ? " EC " : " ?? ",
			objects.data[i].bits,
			objects.data[i].verify_public == 1 ? " ./ " : "    ",
			objects.data[i].sign ? "[./] " : "[  ] ",
			objects.data[i].verify ? " [./] " : " [  ] ",
			objects.data[i].encrypt ? "[./] " : "[  ] ",
			objects.data[i].decrypt ? " [./] " : " [  ] ",
			objects.data[i].label);
		for (int j = 0; j < objects.data[i].num_mechs; j++)
			printf("         [ %-18s ] [   %s    ] [   %s    ]\n",
				get_mechanism_name(objects.data[i].mechs[j].mech),
				objects.data[i].mechs[j].flags & VERIFY_SIGN ? "[./]" : "    ",
				objects.data[i].mechs[j].flags & VERIFY_DECRYPT ? "[./]" : "    ");
		printf("\n");
	}
	printf(" Public == Cert ----------^       ^  ^  ^       ^  ^  ^\n");
	printf(" Sign Attribute ------------------'  |  |       |  |  '---- Decrypt Attribute\n");
	printf(" Sign&Verify functionality ----------'  |       |  '------- Enc&Dec functionality\n");
	printf(" Verify Attribute ----------------------'       '---------- Encrypt functionaliy\n");

	clean_all_objects(&objects);
}

static void ec_sign_size_test(void **state) {

	token_info_t *info = (token_info_t *) *state;

	test_certs_t objects;
	objects.count = 0;
	objects.data = NULL;

	search_for_all_objects(&objects, info);

	debug_print("\nCheck functionality of Sign&Verify and/or Encrypt&Decrypt");
	for (unsigned int i = 0; i < objects.count; i++) {
		if (objects.data[i].key_type == CKK_EC)
			// for (int j = 0; j < objects.data[i].num_mechs; j++) // XXX single mechanism
			for (int l = 30; l < 35; l++)
				sign_verify_test(&(objects.data[i]), info,
					&(objects.data[i].mechs[0]), l);
	}

	clean_all_objects(&objects);
}

static void supported_mechanisms_test(void **state) {
	token_info_t *info = (token_info_t *) *state;
	CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

	CK_RV rv;
	CK_ULONG mechanism_count, i;
	CK_MECHANISM_TYPE_PTR mechanism_list;
	CK_MECHANISM_INFO_PTR mechanism_info;

	if(initialize_cryptoki(info)) {
		fail_msg("CRYPTOKI couldn't be initialized\n");
	}

	rv = function_pointer->C_GetMechanismList(info->slot_id, NULL_PTR, &mechanism_count);
	assert_int_not_equal(mechanism_count,0);
	if ((rv == CKR_OK) && (mechanism_count > 0)) {
		mechanism_list = (CK_MECHANISM_TYPE_PTR) malloc(mechanism_count * sizeof(CK_MECHANISM_TYPE));
		rv = function_pointer->C_GetMechanismList(info->slot_id, mechanism_list, &mechanism_count);
		if (rv != CKR_OK) {
			free(mechanism_list);
			function_pointer->C_Finalize(NULL_PTR);
			fail_msg("Could not get mechanism list!\n");
		}
		assert_non_null(mechanism_list);

		mechanism_info = (CK_MECHANISM_INFO_PTR) malloc(mechanism_count * sizeof(CK_MECHANISM_INFO));

		for (i=0; i< mechanism_count; i++) {
			CK_MECHANISM_TYPE mechanism_type = mechanism_list[i];
			rv = function_pointer->C_GetMechanismInfo(info->slot_id,
				mechanism_type, &mechanism_info[i]);

			if(rv != CKR_OK){
				continue;
			}
		}

		printf("[    MECHANISM    ] [ KEY SIZE ] [  FLAGS   ]\n");
		printf("[                 ] [ MIN][ MAX] [          ]\n");
		for (i = 0; i < mechanism_count; i++) {
			printf("[%-17s] [%4lu][%4lu] [%10s]", get_mechanism_name(mechanism_list[i]),
				mechanism_info[i].ulMinKeySize, mechanism_info[i].ulMaxKeySize,
				get_mechanism_flag_name(mechanism_info[i].flags));
			for (CK_FLAGS j = 1; j <= CKF_EC_COMPRESS; j = j<<1)
				if ((mechanism_info[i].flags & j) != 0)
					printf(" %s", get_mechanism_flag_name(j));
			printf("\n");
		}
		free(mechanism_list);
		free(mechanism_info);
	}

	rv = function_pointer->C_Finalize(NULL_PTR);
	if(rv != CKR_OK){
		fail_msg("Could not finalize CRYPTOKI!\n");
	}
}

int main(int argc, char** argv) {

	char command;
	const struct CMUnitTest readonly_tests_without_initialization[] = {
		/* Check all the mechanisms provided by the token */
		cmocka_unit_test(supported_mechanisms_test),

		/* Regression test Sign&Verify with various data lengths */
		cmocka_unit_test_setup_teardown(ec_sign_size_test,
			clear_token_with_user_login_setup, after_test_cleanup),

		/* Complex readonly test of all objects on the card */
		cmocka_unit_test_setup_teardown(readonly_tests,
			clear_token_with_user_login_setup, after_test_cleanup),
	};

	init_card_info();
	library_path = NULL;

	while ((command = getopt(argc, argv, "?hm:p:")) != -1) {
		switch (command) {
			case 'm':
				library_path = strdup(optarg);
				break;
			case 'p':
				card_info.pin = (CK_UTF8CHAR*) strdup(optarg);
				card_info.pin_length = strlen(optarg);
				break;
			case 'h':
			case '?':
				display_usage();
				return 0;
			default:
				break;
		}
	}

	if (library_path == NULL) {
		debug_print("Falling back to the default library " DEFAULT_P11LIB);
		library_path = strdup(DEFAULT_P11LIB);
	}

	if(set_card_info()) {
		fprintf(stderr, "Could not set card info!\n");
		return 1;
	}

	debug_print("Card info:\n\tPIN %s\n\tCHANGE_PIN %s\n\tPIN LENGTH %d\n\tID 0x%02x\n\tID LENGTH %d",
		card_info.pin, card_info.change_pin, card_info.pin_length, card_info.id[0], card_info.id_length);

	return cmocka_run_group_tests(readonly_tests_without_initialization,
		group_setup, group_teardown);
}

