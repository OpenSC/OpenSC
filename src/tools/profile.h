/*
 * Card profile information
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 */

#ifndef _OPENSC_PROFILE_H
#define _OPENSC_PROFILE_H

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include "opensc-pkcs15.h"

#ifndef SC_PKCS15_PROFILE_DIRECTORY
#define SC_PKCS15_PROFILE_DIRECTORY	"/usr/lib/opensc/profiles"
#endif
#ifndef SC_PKCS15_PROFILE_SUFFIX
#define SC_PKCS15_PROFILE_SUFFIX	"profile"
#endif

struct auth_info {
	struct auth_info *	next;
	unsigned int		type;		/* CHV, AUT, PRO */
	unsigned int		id;		/* CHV1, KEY0, ... */
	unsigned int		ref;
	size_t			key_len;
	u8			key[32];
};

struct file_info {
	char *			ident;
	struct file_info *	next;
	struct sc_file *	file;
	struct file_info *	parent;

	/* PKCS15 book-keeping info */
	/*
	struct {
		unsigned int	fileno;
		unsigned int	type;
	}			pkcs15;
	 */
};

/* For now, we assume the PUK always resides
 * in the same file as the PIN
 */
struct pin_info {
	char *			ident;
	unsigned int		id;		/* 1 == CHV1, 2 == CHV2 */
	struct pin_info *	next;
	struct file_info *	file;
	unsigned int		file_offset;
	unsigned int		attempt[2];

	struct sc_pkcs15_object	pkcs15_obj;
	struct sc_pkcs15_pin_info pkcs15;

	/* These are set while initializing the card */
	char *			secret[2];
};

struct sc_key_template {
	char *			ident;
	struct sc_key_template *next;
	struct sc_file *	file;
	unsigned int		index;	/* translates to file offset */
	struct sc_acl_entry *	key_acl;/* PINs for key usage */

	struct sc_pkcs15_object	pkcs15_obj;
	union {
		struct sc_pkcs15_prkey_info priv;
		struct sc_pkcs15_pubkey_info pub;
	} pkcs15;
};

struct sc_cert_template {
	char *			ident;
	struct sc_cert_template *next;
	struct sc_file *	file;
	struct sc_pkcs15_object	pkcs15_obj;
	struct sc_pkcs15_cert_info pkcs15;
};

struct sc_profile {
	char *			driver;
	struct pkcs15_init_operations *ops;

	struct file_info	mf_info;
	struct file_info	df_info;
	struct file_info *	ef_list;
	struct sc_file *	df[SC_PKCS15_DF_TYPE_COUNT];

	struct pin_info *	pin_list;
	struct auth_info *	auth_list;
	struct sc_key_template *prkey_list;
	struct sc_key_template *pubkey_list;
	struct sc_cert_template *cert_list;

	unsigned int		pin_maxlen;
	unsigned int		pin_minlen;
	unsigned int		pin_pad_char;
	unsigned int		pin_encoding;
	unsigned int		rsa_access_flags;
	unsigned int		dsa_access_flags;

	/* PKCS15 information */
	struct sc_pkcs15_card *	p15_card;
	char *			p15_label;
	char *			p15_manufacturer;
	char *			p15_serial;
};

void		sc_profile_init(struct sc_profile *);
int		sc_profile_load(struct sc_profile *, const char *);
int		sc_profile_finish(struct sc_profile *);
int		sc_profile_build_pkcs15(struct sc_profile *);
struct file_info *sc_profile_find_file(struct sc_profile *, const char *);
struct file_info *sc_profile_find_file_by_path(struct sc_profile *,
			const struct sc_path *);
struct pin_info *sc_profile_find_pin(struct sc_profile *, const char *);
struct sc_key_template *sc_profile_find_private_key(struct sc_profile *,
				const char *);
struct sc_key_template *sc_profile_find_public_key(struct sc_profile *, const char *);
struct auth_info *sc_profile_find_key(struct sc_profile *,
			       unsigned int, unsigned int);
struct sc_cert_template *sc_profile_find_cert(struct sc_profile *,
				const char *);

#endif /* _OPENSC_PROFILE_H */
