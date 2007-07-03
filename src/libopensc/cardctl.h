/*
 * cardctl.h: card_ctl command numbers
 *
 * Copyright (C) 2003  Olaf Kirch <okir@lse.de>
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

#ifndef _OPENSC_CARDCTL_H
#define _OPENSC_CARDCTL_H

#include <opensc/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _CTL_PREFIX(a, b, c) (((a) << 24) | ((b) << 16) | ((c) << 8))

enum {
	/*
	 * Generic card_ctl calls
	 */
	SC_CARDCTL_GENERIC_BASE = 0x00000000,
	SC_CARDCTL_ERASE_CARD,
	SC_CARDCTL_GET_DEFAULT_KEY,
	SC_CARDCTL_LIFECYCLE_GET,
	SC_CARDCTL_LIFECYCLE_SET,
	SC_CARDCTL_GET_SERIALNR,

	/*
	 * GPK specific calls
	 */
	SC_CARDCTL_GPK_BASE = _CTL_PREFIX('G', 'P', 'K'),
	SC_CARDCTL_GPK_VARIANT,
	SC_CARDCTL_GPK_LOCK,
	SC_CARDCTL_GPK_PKINIT,
	SC_CARDCTL_GPK_PKLOAD,
	SC_CARDCTL_GPK_IS_LOCKED,
	SC_CARDCTL_GPK_GENERATE_KEY,

	/*
	 * Cryptoflex specific calls
	 */
	SC_CARDCTL_CRYPTOFLEX_BASE = _CTL_PREFIX('C', 'F', 'X'),
	SC_CARDCTL_CRYPTOFLEX_GENERATE_KEY,

	/*
	 * MioCOS specific calls
	 */
	SC_CARDCTL_MIOCOS_BASE = _CTL_PREFIX('M', 'I', 'O'),
	SC_CARDCTL_MIOCOS_CREATE_AC,

	/*
	 * TCOS specific calls
	 */
	SC_CARDCTL_TCOS_BASE = _CTL_PREFIX('T','C','S'),
	SC_CARDCTL_TCOS_SETPERM,

	/*
	 * CardOS specific calls
	 * (formerly known as "etoken" driver, thus ETK as prefix)
	 */
	SC_CARDCTL_CARDOS_BASE = _CTL_PREFIX('E', 'T', 'K'),
	SC_CARDCTL_CARDOS_PUT_DATA_FCI,
	SC_CARDCTL_CARDOS_PUT_DATA_OCI,
	SC_CARDCTL_CARDOS_PUT_DATA_SECI,
	SC_CARDCTL_CARDOS_GENERATE_KEY,

	/*
	 * Starcos SPK 2.3 specific calls
	 */
	SC_CARDCTL_STARCOS_BASE = _CTL_PREFIX('S', 'T', 'A'),
	SC_CARDCTL_STARCOS_CREATE_FILE,
	SC_CARDCTL_STARCOS_CREATE_END,
	SC_CARDCTL_STARCOS_WRITE_KEY,
	SC_CARDCTL_STARCOS_GENERATE_KEY,

	/*
	 * JCOP specific calls
	 */
	SC_CARDCTL_JCOP_BASE = _CTL_PREFIX('J', 'C', 'P'),
	SC_CARDCTL_JCOP_LOCK,
	SC_CARDCTL_JCOP_GENERATE_KEY,

	/*
	 * Oberthur specific calls
	 */
	SC_CARDCTL_OBERTHUR_BASE = _CTL_PREFIX('O', 'B', 'R'),
	SC_CARDCTL_OBERTHUR_UPDATE_KEY,
	SC_CARDCTL_OBERTHUR_GENERATE_KEY,
	SC_CARDCTL_OBERTHUR_CREATE_PIN,

	/*
	 * Setcos specific calls
	 */
	SC_CARDCTL_SETCOS_BASE = _CTL_PREFIX('S', 'E', 'T'),
	SC_CARDCTL_SETCOS_PUTDATA,
	SC_CARDCTL_SETCOS_GETDATA,
	SC_CARDCTL_SETCOS_GENERATE_STORE_KEY,
	SC_CARDCTL_SETCOS_ACTIVATE_FILE,

	/*
	 * Incrypto34 specific calls
	 */
	SC_CARDCTL_INCRYPTO34_BASE = _CTL_PREFIX('I', '3', '4'),
	SC_CARDCTL_INCRYPTO34_PUT_DATA_FCI,
	SC_CARDCTL_INCRYPTO34_PUT_DATA_OCI,
	SC_CARDCTL_INCRYPTO34_PUT_DATA_SECI,
	SC_CARDCTL_INCRYPTO34_GENERATE_KEY,
	SC_CARDCTL_INCRYPTO34_CHANGE_KEY_DATA,
	SC_CARDCTL_INCRYPTO34_ERASE_FILES,
	
	/*
	 * Muscle specific calls
	 */
	SC_CARDCTL_MUSCLE_BASE = _CTL_PREFIX('M','S','C'),
	SC_CARDCTL_MUSCLE_GENERATE_KEY,
	SC_CARDCTL_MUSCLE_EXTRACT_KEY,
	SC_CARDCTL_MUSCLE_IMPORT_KEY,
	SC_CARDCTL_MUSCLE_VERIFIED_PINS,

	/*
	 * ASEPCOS specific calls
	 */
	SC_CARDCTL_ASEPCOS_BASE = _CTL_PREFIX('A','S','E'),
	SC_CARDCTL_ASEPCOS_CHANGE_KEY,
	SC_CARDCTL_ASEPCOS_AKN2FILEID,
	SC_CARDCTL_ASEPCOS_SET_SATTR,
	SC_CARDCTL_ASEPCOS_ACTIVATE_FILE
};

enum {
	SC_CARDCTRL_LIFECYCLE_ADMIN,
	SC_CARDCTRL_LIFECYCLE_USER,
	SC_CARDCTRL_LIFECYCLE_OTHER
};

/*
 * Generic cardctl - check if the required key is a default
 * key (such as the GPK "TEST KEYTEST KEY" key, or the Cryptoflex AAK)
 */
struct sc_cardctl_default_key {
	int		method;		/* SC_AC_XXX */
	int		key_ref;	/* key reference */

	size_t		len;		/* in: max size, out: actual size */
	u8 *		key_data;	/* out: key data */
};

/*
 * GPK lock file.
 * Parent DF of file must be selected.
 */
struct sc_cardctl_gpk_lock {
	struct sc_file *	file;
	unsigned int		operation;
};

/*
 * GPK initialize private key file.
 * Parent DF must be selected.
 */
struct sc_cardctl_gpk_pkinit {
	struct sc_file *	file;
	unsigned int		privlen;
};

/*
 * GPK load private key portion.
 */
struct sc_cardctl_gpk_pkload {
	struct sc_file *	file;
	u8 *			data;
	unsigned int		len;
	unsigned int		datalen;
};

struct sc_cardctl_gpk_genkey {
	unsigned int		fid;
	unsigned int		privlen;
	unsigned char *		pubkey;
	unsigned int		pubkey_len;
};

enum {
	SC_CARDCTL_MIOCOS_AC_PIN,
	SC_CARDCTL_MIOCOS_AC_CHAL,
	SC_CARDCTL_MIOCOS_AC_LOGICAL,
	SC_CARDCTL_MIOCOS_AC_SMARTPIN
};

/*
 * MioCOS AC info
 */
struct sc_cardctl_miocos_ac_info {
	int type;
	int ref;
	int max_tries;
	int enable_ac;		/* only applicable to PINs */
	u8 key_value[8];
	int max_unblock_tries;	/* same here */
	u8 unblock_value[8];	/* and here */
};

/*
 * Siemens CardOS PIN info
 */
struct sc_cardctl_cardos_obj_info {
	u8 *		data;
	size_t		len;
};

struct sc_cardctl_cardos_genkey_info {
	unsigned int	key_id;
	unsigned int	key_bits;
	unsigned short	fid;
};

/*
 * Incrypto34 PIN info
 */
struct sc_cardctl_incrypto34_obj_info {
	u8 *		data;
	size_t		len;
	unsigned int	key_id;
	unsigned int	key_class;
};

struct sc_cardctl_incrypto34_genkey_info {
	unsigned int	key_id;
	unsigned int	key_bits;
	unsigned short	fid;
};

/*
 * Cryptoflex info
 */
struct sc_cardctl_cryptoflex_genkey_info {
	unsigned int	key_num;
	unsigned int	key_bits;
	unsigned long	exponent;
	unsigned char *	pubkey;
	unsigned int	pubkey_len;
};

/*
 * Starcos stuff
 */
#define	SC_STARCOS_MF_DATA	0x01
#define SC_STARCOS_DF_DATA	0x02
#define SC_STARCOS_EF_DATA	0x04

typedef struct sc_starcos_create_data_st {
	unsigned int type;
	union {
		struct {
			u8 header[19];	/* see starcos manual */
		} mf;
		struct {
			u8 header[25];	/* see starcos manual */
			u8 size[2];
		} df;
		struct {
			u8 header[16];	/* see starcos manual */
		} ef;
	} data;
} sc_starcos_create_data;

typedef struct sc_starcos_write_key_data_st {
	u8	mode;		/* 1 = Update, 0 = Install */
	u8	kid;		/* key id                  */
	u8	key_header[12];	/* see starcos manual      */
	const u8 *key;
	size_t	key_len;
} sc_starcos_wkey_data;

typedef struct sc_starcos_gen_key_data_st {
	u8	key_id;
	size_t	key_length;
	u8	*modulus;
} sc_starcos_gen_key_data;

struct sc_cardctl_jcop_genkey  {
     unsigned long exponent;
     sc_path_t pub_file_ref;
     sc_path_t pri_file_ref;
     unsigned char *	pubkey;
     unsigned int	pubkey_len;
};

/*
 * Oberthur ex_data stuff
 */
enum SC_CARDCTL_OBERTHUR_KEY_TYPE {
	SC_CARDCTL_OBERTHUR_KEY_DES = 0x80,

	SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC = 0xA1,
	SC_CARDCTL_OBERTHUR_KEY_RSA_SFM,
	SC_CARDCTL_OBERTHUR_KEY_RSA_CRT,
	SC_CARDCTL_OBERTHUR_KEY_DSA_PUBLIC,
	SC_CARDCTL_OBERTHUR_KEY_DSA_PRIVATE
};

struct sc_cardctl_oberthur_genkey_info {
	unsigned int    id_prv, id_pub;
	unsigned int    key_bits;
	unsigned long   exponent;
	unsigned char * pubkey;
	unsigned int    pubkey_len;

	int     method;     /* SC_AC_XXX */
	int     key_ref;    /* key reference */		
};

struct sc_cardctl_oberthur_updatekey_info {
	enum SC_CARDCTL_OBERTHUR_KEY_TYPE  type;

	unsigned char   *data;
	unsigned int    data_len;

	unsigned char   id[256];
	unsigned int    id_len;
};

struct sc_cardctl_oberthur_createpin_info {
	unsigned int type;
	unsigned int ref;
	const unsigned char *pin;
	unsigned int pin_len;
	unsigned int pin_tries;
	const unsigned char *puk;
	unsigned int puk_len;
	unsigned int puk_tries;
};

/*
 * Setcos stuff
 */
struct sc_cardctl_setcos_data_obj {
	int     P1;
	int     P2;
	u8 *    Data;
	size_t  DataLen;
	int     LengthMax;
};

#define OP_TYPE_GENERATE	0
#define OP_TYPE_STORE		1

struct sc_cardctl_setcos_gen_store_key_info {
	int             op_type;
	unsigned int    mod_len;     /* in bits */
	unsigned int    pubexp_len;  /* in bits */
	unsigned char  *pubexp;
	unsigned int    primep_len;  /* in bits */
	unsigned char  *primep;
	unsigned int    primeq_len;  /* in bits */
	unsigned char  *primeq;
};

/*
 * Muscle stuff
 */
typedef struct sc_cardctl_muscle_gen_key_info {
	int 	keyType;
	int 	keySize;
	int 	privateKeyLocation;
	int 	publicKeyLocation;
} sc_cardctl_muscle_gen_key_info_t;


typedef struct sc_cardctl_muscle_key_info {
	int 	keyType;
	int 	keyLocation;
	int 	keySize;
	int 	modLength;
	u8* 	modValue;
	int 	expLength;
	u8* 	expValue;
	int 	pLength;
	u8* 	pValue;
	int 	qLength;
	u8* 	qValue;
	int 	pqLength;
	u8* 	pqValue;
	int 	dp1Length;
	u8* 	dp1Value;
	int 	dq1Length;
	u8* 	dq1Value;
	int 	gLength;
	u8* 	gValue;
	int 	yLength;
	u8* 	yValue;
} sc_cardctl_muscle_key_info_t;

typedef struct sc_cardctl_muscle_verified_pins_info {
	unsigned	verifiedPins;
} sc_cardctl_muscle_verified_pins_info_t;

/* ASEPCOS ctl specific structures */
typedef struct sc_cardctl_asepcos_change_key {
	const u8 *data;
	size_t datalen;
} sc_cardctl_asepcos_change_key_t;

typedef struct sc_cardctl_asepcos_akn2fileid {
	int akn;
	int fileid;
} sc_cardctl_asepcos_akn2fileid_t;

typedef struct sc_cardctl_asepcos_activate_file {
	int	fileid;
	int	is_ef;
} sc_cardctl_asepcos_activate_file_t;

#ifdef __cplusplus
}
#endif

#endif /* _OPENSC_CARDCTL_H */
