/*
 * Card profile information
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 */

#ifndef _OPENSC_PROFILE_H
#define _OPENSC_PROFILE_H

#include "opensc-pkcs15.h"

struct auth_info {
	struct auth_info *	next;
	unsigned int		type;		/* CHV, AUT, PRO */
	unsigned int		id;		/* CHV1, KEY0, ... */
	unsigned int		ref;
	size_t			key_len;
	u_int8_t		key[32];
};

struct file_info {
	char *			ident;
	struct file_info *	next;
	struct sc_file *	file;

	/* PKCS15 book-keeping info */
	struct {
		unsigned int	fileno;
		unsigned int	type;
	}			pkcs15;
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

	struct sc_pkcs15_pin_info pkcs15;

	/* These are set while initializing the card */
	char *			secret[2];
};

struct prkey_info {
	char *			ident;
	struct prkey_info *	next;
	struct file_info *	file;
	unsigned int		type;
	unsigned int		index;	/* translates to file offset */

	struct sc_pkcs15_prkey_info pkcs15;
};

struct sc_profile {
	char *			driver;
	int			(*erase_card)(struct sc_profile *,
					struct sc_card *);
	int			(*init_app)(struct sc_profile *,
					struct sc_card *);

	struct file_info	mf_info;
	struct file_info	df_info;
	struct file_info *	ef_list;
	struct pin_info *	pin_list;
	struct auth_info *	auth_list;
	struct prkey_info *	prkey_list;

	unsigned int		pin_maxlen;
	unsigned int		pin_minlen;
	unsigned int		pin_pad_char;

	/* PKCS15 information */
	struct sc_pkcs15_card *	p15_card;
	char *			p15_label;
	char *			p15_manufacturer;
	char *			p15_serial;
};

void		sc_profile_init(struct sc_profile *, struct sc_pkcs15_card *);
int		sc_profile_load(struct sc_profile *, const char *);
int		sc_profile_finish(struct sc_profile *);
int		sc_profile_build_pkcs15(struct sc_profile *);
struct file_info *sc_profile_find_file(struct sc_profile *, const char *);
struct file_info *sc_profile_file_info(struct sc_profile *, struct sc_file *);
struct pin_info *sc_profile_find_pin(struct sc_profile *, const char *);
struct prkey_info *sc_profile_find_prkey(struct sc_profile *, const char *);
struct auth_info *sc_profile_find_key(struct sc_profile *,
			       unsigned int, unsigned int);

#endif /* _OPENSC_PROFILE_H */
