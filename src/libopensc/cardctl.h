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

#include <time.h>
#include "libopensc/types.h"

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
	SC_CARDCTL_GET_SE_INFO,
	SC_CARDCTL_GET_CHV_REFERENCE_IN_SE,
	SC_CARDCTL_PKCS11_INIT_TOKEN,
	SC_CARDCTL_PKCS11_INIT_PIN,

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
	SC_CARDCTL_ASEPCOS_ACTIVATE_FILE,

 	/*
	 * ruToken specific calls
	 */
 	SC_CARDCTL_RUTOKEN_BASE = _CTL_PREFIX('R', 'T', 'K'),
 	/*  PUT_DATA  */
 	SC_CARDCTL_RUTOKEN_CREATE_DO,
 	SC_CARDCTL_RUTOKEN_CHANGE_DO,
 	SC_CARDCTL_RUTOKEN_GENERATE_KEY_DO,
 	SC_CARDCTL_RUTOKEN_DELETE_DO,
 	SC_CARDCTL_RUTOKEN_GET_INFO,
 	/* NON STANDARD  */
 	SC_CARDCTL_RUTOKEN_GET_DO_INFO,
 	SC_CARDCTL_RUTOKEN_GOST_ENCIPHER, 
 	SC_CARDCTL_RUTOKEN_GOST_DECIPHER,
	SC_CARDCTL_RUTOKEN_FORMAT_INIT,
	SC_CARDCTL_RUTOKEN_FORMAT_END,

	/*
	 * EnterSafe specific calls
	 */
	SC_CARDCTL_ENTERSAFE_BASE = _CTL_PREFIX('E', 'S', 'F'),
	SC_CARDCTL_ENTERSAFE_CREATE_FILE,
	SC_CARDCTL_ENTERSAFE_CREATE_END,
	SC_CARDCTL_ENTERSAFE_WRITE_KEY,
	SC_CARDCTL_ENTERSAFE_GENERATE_KEY,
	SC_CARDCTL_ENTERSAFE_PREINSTALL_KEYS,

	/*
	 * Rutoken ECP specific calls
	 */
	SC_CARDCTL_RTECP_BASE = _CTL_PREFIX('R', 'T', 'E'),
	SC_CARDCTL_RTECP_INIT,
	SC_CARDCTL_RTECP_INIT_END,
	SC_CARDCTL_RTECP_GENERATE_KEY,

	/*
	* Westcos specific
	*/
	SC_CARDCTL_WESTCOS_FREEZE = _CTL_PREFIX('W', 'T', 'C'),
	SC_CARDCTL_WESTCOS_CREATE_MF,
	SC_CARDCTL_WESTCOS_COMMIT,
	SC_CARDCTL_WESTCOS_ROLLBACK,
	SC_CARDCTL_WESTCOS_AUT_KEY,
	SC_CARDCTL_WESTCOS_CHANGE_KEY,
	SC_CARDCTL_WESTCOS_SET_DEFAULT_KEY,
	SC_CARDCTL_WESTCOS_LOAD_DATA,

	/*
	 * MyEID specific calls
	 */
	SC_CARDCTL_MYEID_BASE = _CTL_PREFIX('M', 'Y', 'E'),
	SC_CARDCTL_MYEID_PUTDATA,
	SC_CARDCTL_MYEID_GETDATA,
	SC_CARDCTL_MYEID_GENERATE_STORE_KEY,
	SC_CARDCTL_MYEID_ACTIVATE_CARD,

	/*
	 * PIV specific calls
	 */
	SC_CARDCTL_PIV_BASE = _CTL_PREFIX('P', 'I', 'V'),
	SC_CARDCTL_PIV_AUTHENTICATE,
	SC_CARDCTL_PIV_GENERATE_KEY,
	SC_CARDCTL_PIV_PIN_PREFERENCE,
	SC_CARDCTL_PIV_OBJECT_PRESENT,

	/*
	 * CAC specific calls
	 */
	SC_CARDCTL_CAC_BASE = _CTL_PREFIX('C', 'A', 'C'),
	SC_CARDCTL_CAC_INIT_GET_GENERIC_OBJECTS,
	SC_CARDCTL_CAC_GET_NEXT_GENERIC_OBJECT,
	SC_CARDCTL_CAC_FINAL_GET_GENERIC_OBJECTS,
	SC_CARDCTL_CAC_INIT_GET_CERT_OBJECTS,
	SC_CARDCTL_CAC_GET_NEXT_CERT_OBJECT,
	SC_CARDCTL_CAC_FINAL_GET_CERT_OBJECTS,
	SC_CARDCTL_CAC_GET_ACA_PATH,

        /*
	 * AuthentIC v3
	 */
        SC_CARDCTL_AUTHENTIC_BASE = _CTL_PREFIX('A','V','3'),
        SC_CARDCTL_AUTHENTIC_SDO_CREATE,
        SC_CARDCTL_AUTHENTIC_SDO_DELETE,
        SC_CARDCTL_AUTHENTIC_SDO_STORE,
        SC_CARDCTL_AUTHENTIC_SDO_GENERATE,

	/*
	 * Coolkey specific calls
	 */
	SC_CARDCTL_COOLKEY_BASE = _CTL_PREFIX('C', 'O', 'K'),
	SC_CARDCTL_COOLKEY_INIT_GET_OBJECTS,
	SC_CARDCTL_COOLKEY_GET_NEXT_OBJECT,
	SC_CARDCTL_COOLKEY_FINAL_GET_OBJECTS,
	SC_CARDCTL_COOLKEY_GET_ATTRIBUTE,
	SC_CARDCTL_COOLKEY_GET_TOKEN_INFO,
	SC_CARDCTL_COOLKEY_FIND_OBJECT,

        /*
	 * IAS/ECC
	 */
	SC_CARDCTL_IASECC_BASE = _CTL_PREFIX('E','C','C'),
	SC_CARDCTL_IASECC_GET_FREE_KEY_REFERENCE,
	SC_CARDCTL_IASECC_SDO_MAGIC = _CTL_PREFIX('S','D','O') | 'M',
	SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA = _CTL_PREFIX('S','D','O') | 'P',
	SC_CARDCTL_IASECC_SDO_PUT_DATA,
	SC_CARDCTL_IASECC_SDO_KEY_RSA_PUT_DATA,
	SC_CARDCTL_IASECC_SDO_GET_DATA,
	SC_CARDCTL_IASECC_SDO_GENERATE,
	SC_CARDCTL_IASECC_SDO_CREATE,
	SC_CARDCTL_IASECC_SDO_DELETE,

	/*
	 * OpenPGP
	 */
	SC_CARDCTL_OPENPGP_BASE = _CTL_PREFIX('P', 'G', 'P'),
	SC_CARDCTL_OPENPGP_GENERATE_KEY,
	SC_CARDCTL_OPENPGP_STORE_KEY,

	/*
	 * SmartCard-HSM
	 */
	SC_CARDCTL_SC_HSMP_BASE = _CTL_PREFIX('S', 'C', 'H'),
	SC_CARDCTL_SC_HSM_GENERATE_KEY,
	SC_CARDCTL_SC_HSM_INITIALIZE,
	SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE,
	SC_CARDCTL_SC_HSM_WRAP_KEY,
	SC_CARDCTL_SC_HSM_UNWRAP_KEY,

	/*
	 * DNIe specific calls
	 */
    SC_CARDCTL_DNIE_BASE = _CTL_PREFIX('D', 'N', 'I'),
	SC_CARDCTL_DNIE_GENERATE_KEY,
	SC_CARDCTL_DNIE_GET_INFO,

	/*
	 * isoApplet Java Card Applet
	 */
	SC_CARDCTL_ISOAPPLET_BASE = _CTL_PREFIX('I','S','O'),
	SC_CARDCTL_ISOAPPLET_GENERATE_KEY,
	SC_CARDCTL_ISOAPPLET_IMPORT_KEY,

	/*
	 * GIDS cards
	 */
	SC_CARDCTL_GIDS_BASE = _CTL_PREFIX('G','I','D'),
	SC_CARDCTL_GIDS_GET_ALL_CONTAINERS,
	SC_CARDCTL_GIDS_GET_CONTAINER_DETAIL,
	SC_CARDCTL_GIDS_SELECT_KEY_REFERENCE,
	SC_CARDCTL_GIDS_CREATE_KEY,
	SC_CARDCTL_GIDS_GENERATE_KEY,
	SC_CARDCTL_GIDS_IMPORT_KEY,
	SC_CARDCTL_GIDS_SAVE_CERT,
	SC_CARDCTL_GIDS_DELETE_KEY,
	SC_CARDCTL_GIDS_DELETE_CERT,
	SC_CARDCTL_GIDS_INITIALIZE,
	SC_CARDCTL_GIDS_SET_ADMIN_KEY,
	SC_CARDCTL_GIDS_AUTHENTICATE_ADMIN,

	/*
	 * IDPrime specific calls
	 */
	SC_CARDCTL_IDPRIME_BASE = _CTL_PREFIX('I', 'D', 'P'),
	SC_CARDCTL_IDPRIME_INIT_GET_OBJECTS,
	SC_CARDCTL_IDPRIME_GET_NEXT_OBJECT,
	SC_CARDCTL_IDPRIME_FINAL_GET_OBJECTS,
	SC_CARDCTL_IDPRIME_GET_TOKEN_NAME,

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
 * Generic cardctl - initialize token using PKCS#11 style
 */
typedef struct sc_cardctl_pkcs11_init_token {
	const unsigned char *	so_pin;
	size_t			so_pin_len;
	const char *		label;
} sc_cardctl_pkcs11_init_token_t;

/*
 * Generic cardctl - set pin using PKCS#11 style
 */
typedef struct sc_cardctl_pkcs11_init_pin {
	const unsigned char *	pin;
	size_t			pin_len;
} sc_cardctl_pkcs11_init_pin_t;

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
	SC_CARDCTL_OBERTHUR_KEY_DSA_PRIVATE,
	SC_CARDCTL_OBERTHUR_KEY_EC_CRT,
	SC_CARDCTL_OBERTHUR_KEY_EC_PUBLIC
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
	size_t 	modLength;
	u8* 	modValue;
	size_t 	expLength;
	u8* 	expValue;
	size_t 	pLength;
	u8* 	pValue;
	size_t 	qLength;
	u8* 	qValue;
	size_t 	pqLength;
	u8* 	pqValue;
	size_t 	dp1Length;
	u8* 	dp1Value;
	size_t 	dq1Length;
	u8* 	dq1Value;
	size_t 	gLength;
	u8* 	gValue;
	size_t 	yLength;
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

#define OP_TYPE_GENERATE	0
#define OP_TYPE_STORE		1

/*
 * Westcos
 */

typedef struct {
	int key_reference;
	size_t key_len; /* 8, 16 or 24 */
	u8 key_value[24];
}sc_autkey_t;

typedef struct {
	sc_autkey_t master_key;
	sc_autkey_t new_key;
	u8 key_template[7];
}sc_changekey_t;

/*
 *  RuToken types and constants
 */

#define SC_RUTOKEN_DO_PART_BODY_LEN    199    
#define SC_RUTOKEN_DO_HDR_LEN  32

/*   DO Types  */
#define SC_RUTOKEN_TYPE_MASK             0xF
#define SC_RUTOKEN_TYPE_SE               0x0
#define SC_RUTOKEN_TYPE_CHV              0x1
#define SC_RUTOKEN_TYPE_KEY              0x2

#define SC_RUTOKEN_COMPACT_DO_MAX_LEN  16          /*  MAX Body length of Compact DOs  */

#define SC_RUTOKEN_DO_ALL_MIN_ID       0x1         /*  MIN ID value of All DOs  */
#define SC_RUTOKEN_DO_CHV_MAX_ID       0x1F        /*  MAX ID value of CHV-objects  */
#define SC_RUTOKEN_DO_NOCHV_MAX_ID     0x7F        /*  MAX ID value of All Other DOs  */

/*  DO Default Lengths  */
#define SC_RUTOKEN_DEF_LEN_DO_GOST         32
#define SC_RUTOKEN_DEF_LEN_DO_SE           6


#define SC_RUTOKEN_ALLTYPE_SE            SC_RUTOKEN_TYPE_SE		/* SE  */
#define SC_RUTOKEN_ALLTYPE_GCHV          SC_RUTOKEN_TYPE_CHV	/* GCHV  */
#define SC_RUTOKEN_ALLTYPE_LCHV          0x11        			/*  LCHV  */
#define SC_RUTOKEN_ALLTYPE_GOST          SC_RUTOKEN_TYPE_KEY	/*  GOST  */

/*  DO ID  */
#define SC_RUTOKEN_ID_CURDF_RESID_FLAG   0x80        /*  DO placed in current DF  */
                                            
#define SC_RUTOKEN_DEF_ID_GCHV_ADMIN       0x01      /*  ID DO ADMIN  */
#define SC_RUTOKEN_DEF_ID_GCHV_USER        0x02      /*  ID DO USER  */

/*  DO Options  */
#define SC_RUTOKEN_OPTIONS_GCHV_ACCESS_MASK  0x7     /*  Access rights  */
#define SC_RUTOKEN_OPTIONS_GACCESS_ADMIN     SC_RUTOKEN_DEF_ID_GCHV_ADMIN   /*  ADMIN  */
#define SC_RUTOKEN_OPTIONS_GACCESS_USER      SC_RUTOKEN_DEF_ID_GCHV_USER    /*  USER  */

#define SC_RUTOKEN_OPTIONS_GOST_CRYPT_MASK   0x7     /*  crypto algorithm  */
#define SC_RUTOKEN_OPTIONS_GOST_CRYPT_PZ     0x0     /*  (encryptECB) simple-change mode  */
#define SC_RUTOKEN_OPTIONS_GOST_CRYPT_GAMM   0x1     /*  (encryptCNT) gamma mode  */
#define SC_RUTOKEN_OPTIONS_GOST_CRYPT_GAMMOS 0x2     /*  (encryptCFB) feed-back gamma mode  */


/*  DO flags  */
#define SC_RUTOKEN_FLAGS_COMPACT_DO      0x1
#define SC_RUTOKEN_FLAGS_OPEN_DO_MASK    0x6
#define SC_RUTOKEN_FLAGS_BLEN_OPEN_DO    0x2
#define SC_RUTOKEN_FLAGS_FULL_OPEN_DO    0x6

/*  DO MAX:CUR try  */
#define SC_RUTOKEN_MAXTRY_MASK           0xF0        /*  MAX try  */
#define SC_RUTOKEN_CURTRY_MASK           0x0F        /*  CUR try  */

#define SC_RUTOKEN_DO_CHV_MAX_ID_V2       SC_RUTOKEN_DEF_ID_GCHV_USER	/*  MAX ID value of CHV-objects  */
#define SC_RUTOKEN_DO_NOCHV_MAX_ID_V2     SC_RUTOKEN_DO_NOCHV_MAX_ID	/*  MAX ID value of All Other DOs  */

#if defined(__APPLE__) || defined(sun)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif
typedef u8 sc_SecAttrV2_t[40];

typedef struct sc_ObjectTypeID{
	u8    byObjectType;
	u8    byObjectID;
} sc_ObjectTypeID_t;

typedef struct sc_ObjectParams{
	u8    byObjectOptions;
	u8    byObjectFlags;
	u8    byObjectTry;
} sc_ObjectParams_t;

typedef struct sc_DOHdrV2 {
	unsigned short		wDOBodyLen;
	sc_ObjectTypeID_t	OTID;
	sc_ObjectParams_t	OP;
	u8					dwReserv1[4];
	u8					abyReserv2[6];
	sc_SecAttrV2_t		SA_V2;
} sc_DOHdrV2_t;

typedef struct sc_DO_V2 {
	sc_DOHdrV2_t	HDR;
	u8				abyDOBody[SC_RUTOKEN_DO_PART_BODY_LEN];
} sc_DO_V2_t;

typedef enum
{
	select_first,
	select_by_id,
	select_next
} SC_RUTOKEN_DO_SEL_TYPES;

typedef struct sc_DO_INFO_V2 {
	u8						DoId;
	SC_RUTOKEN_DO_SEL_TYPES	SelType;
	u8						pDoData[256];
} sc_DO_INFO_t;

struct sc_rutoken_decipherinfo {
	const u8	*inbuf;
    size_t inlen;
    u8	*outbuf;
    size_t outlen;
};

/*
 * EnterSafe stuff
 * 
 */

#define	SC_ENTERSAFE_MF_DATA	0x01
#define SC_ENTERSAFE_DF_DATA	0x02
#define SC_ENTERSAFE_EF_DATA	0x04

#define ENTERSAFE_USER_PIN_ID  0x01
#define ENTERSAFE_SO_PIN_ID 0x02
#define ENTERSAFE_MIN_KEY_ID 0x01
#define ENTERSAFE_MAX_KEY_ID 0x09

#define ENTERSAFE_AC_EVERYONE 0x00
#define ENTERSAFE_AC_USER 0x04

#define ENTERSAFE_AC_NEVER 0xC0
#define ENTERSAFE_AC_ALWAYS 0x10
#define ENTERSAFE_AC_CHV 0x30


typedef struct sc_entersafe_create_data_st {
	 unsigned int type;
	 union {
		  struct {
			   u8 file_id[2];
			   u8 file_count;
			   u8 flag;
			   u8 ikf_size[2];
			   u8 create_ac;
			   u8 append_ac;
			   u8 lock_ac;
			   u8 aid[16];
			   u8 init_key[16];
		  } df;
		  struct {
			   u8 file_id[2];	
			   u8 size[2];
			   u8 attr[2];
			   u8 name;
			   u8 ac[10];
			   u8 sm[2];
		  } ef;
	 } data;
} sc_entersafe_create_data;

typedef struct sc_entersafe_wkey_data_st {
	 u8 key_id;
	 u8 usage;
	 union{
		  struct sc_pkcs15_prkey_rsa* rsa;
		  struct{
			   u8 EC;
			   u8 ver;
			   u8 key_val[256];
			   size_t key_len;
		  } symmetric;
	 }key_data;
} sc_entersafe_wkey_data;

typedef struct sc_entersafe_gen_key_data_st {
	u8	key_id;
	size_t	key_length;
	u8	*modulus;
} sc_entersafe_gen_key_data;

#define	SC_EPASS2003_KEY	0x00000010
#define	SC_EPASS2003_KEY_RSA	0x00000011
#define	SC_EPASS2003_SECRET	0x00000020
#define	SC_EPASS2003_SECRET_PRE	0x00000021
#define	SC_EPASS2003_SECRET_PIN	0x00000022

#define EPASS2003_AC_EVERYONE		0x00
#define EPASS2003_AC_USER		0x06
#define EPASS2003_AC_SO			0x08
#define EPASS2003_AC_NOONE		0x0F
#define EPASS2003_AC_MAC_UNEQUAL	0x80
#define EPASS2003_AC_MAC_NOLESS		0x90
#define EPASS2003_AC_MAC_LESS		0xA0
#define EPASS2003_AC_MAC_EQUAL		0xB0

#define FID_STEP 0x20

typedef struct sc_epass2003_wkey_data_st {
	 u8 type;
	 union {
		  struct {
			  unsigned short fid;
			  struct sc_pkcs15_prkey_rsa* rsa;
		  } es_key;
		  struct {
			  u8 kid;
			  u8 EC;
			  u8 ac[2];
			  u8 key_val[256];
			  size_t key_len;
		  } es_secret;
	 } key_data;
} sc_epass2003_wkey_data;

typedef struct sc_epass2003_gen_key_data_st {
	 int prkey_id;
	 int pukey_id;
	 size_t key_length;
	 u8 *modulus;
} sc_epass2003_gen_key_data;


#if defined(__APPLE__) || defined(sun)
#pragma pack()
#else
#pragma pack(pop)
#endif

/*
 * Rutoken ECP stuff
 */

#define SC_RTECP_SEC_ATTR_SIZE 15

typedef struct sc_rtecp_genkey_data {
	unsigned int type;
	unsigned int key_id;
	union
	{
		struct
		{
			unsigned char *exponent;
			size_t exponent_len;
			unsigned char *modulus;
			size_t modulus_len;
		} rsa;
		struct
		{
			unsigned char *xy;
			size_t xy_len;
		} gostr3410;
	} u;
} sc_rtecp_genkey_data_t;

/*
 * MyEID stuff
 */
	enum SC_CARDCTL_MYEID_KEY_TYPE {
		SC_CARDCTL_MYEID_KEY_RSA = 0x11,
		SC_CARDCTL_MYEID_KEY_DES = 0x19,
		SC_CARDCTL_MYEID_KEY_EC  = 0x22,
		SC_CARDCTL_MYEID_KEY_AES = 0x29,
		SC_CARDCTL_MYEID_KEY_GENERIC_SECRET = 0x41
	};

	struct sc_cardctl_myeid_data_obj {
		int     P1;
		int     P2;
		u8 *    Data;
		size_t  DataLen;
		int     LengthMax;
	};

	struct sc_cardctl_myeid_gen_store_key_info {
		int             op_type;
		unsigned int	key_type;			/* value of SC_CARDCTL_MYEID_KEY_TYPE */ 
		size_t    key_len_bits;   
		unsigned char  *mod;
		size_t    pubexp_len;  
		unsigned char  *pubexp;
		size_t    primep_len;  
		unsigned char  *primep;
		size_t    primeq_len;  
		unsigned char  *primeq;
		size_t    dp1_len;  
		unsigned char  *dp1;
		size_t    dq1_len;  
		unsigned char  *dq1;
		size_t    invq_len;  
		unsigned char  *invq;
		/* new for MyEID > 3.6.0 */
		unsigned char  *d;                  /* EC private key / Symmetric key */
		size_t    d_len;              /* EC / Symmetric */
		unsigned char  *ecpublic_point;     /* EC public key */
		size_t    ecpublic_point_len; /* EC */
    };

/*
 * PIV info
 */
typedef struct sc_cardctl_piv_genkey_info_st {
	unsigned int	key_num;
	unsigned int	key_algid;	/* RSA 5, 6, 7; EC 11, 14 */ 
	unsigned int	key_bits;	/* RSA */
	unsigned long	exponent;	/* RSA */
	unsigned char *	pubkey;		/* RSA */
	unsigned int	pubkey_len;	/* RSA */
	unsigned char * ecparam;        /* EC */
	unsigned int    ecparam_len;    /* EC */
	unsigned char * ecpoint;        /* EC */
	unsigned int    ecpoint_len;    /* EC */

} sc_cardctl_piv_genkey_info_t;

/*
 * OpenPGP
 */
#define SC_OPENPGP_KEY_SIGN		1
#define SC_OPENPGP_KEY_ENCR		2
#define SC_OPENPGP_KEY_AUTH		3

#define	SC_OPENPGP_KEYALGO_RSA		0x01
#define	SC_OPENPGP_KEYALGO_ECDH		0x12
#define	SC_OPENPGP_KEYALGO_ECDSA	0x13

#define SC_OPENPGP_KEYFORMAT_RSA_STD	0    /* See 4.3.3.6 Algorithm Attributes */
#define SC_OPENPGP_KEYFORMAT_RSA_STDN	1    /* OpenPGP card spec v2 */
#define SC_OPENPGP_KEYFORMAT_RSA_CRT	2
#define SC_OPENPGP_KEYFORMAT_RSA_CRTN	3

#define SC_OPENPGP_KEYFORMAT_EC_STD	0
#define SC_OPENPGP_KEYFORMAT_EC_STDPUB	0xFF

#define SC_OPENPGP_MAX_EXP_BITS		0x20 /* maximum exponent length supported in bits */

typedef struct sc_cardctl_openpgp_keygen_info {
	u8 key_id;		/* SC_OPENPGP_KEY_... */
	u8 algorithm;		/* SC_OPENPGP_KEYALGO_... */
	union {
		struct {
			u8 keyformat;		/* SC_OPENPGP_KEYFORMAT_RSA_... */
			u8 *modulus;		/* New-generated pubkey info responded from the card */
			size_t modulus_len;	/* Length of modulus in bit */
			u8 *exponent;
			size_t exponent_len;	/* Length of exponent in bit */
		} rsa;
		struct {
			u8 keyformat;	/* SC_OPENPGP_KEYFORMAT_EC_... */
			u8 *ecpoint;
			size_t ecpoint_len;
			struct sc_object_id oid;
			u8 oid_len;
			unsigned int key_length;
		} ec;
	} u;
} sc_cardctl_openpgp_keygen_info_t;

typedef struct sc_cardctl_openpgp_keystore_info {
	u8 key_id;		/* SC_OPENPGP_KEY_... */
	u8 algorithm;		/* SC_OPENPGP_KEYALGO_... */
	union {
		struct {
			u8 keyformat;	/* SC_OPENPGP_KEYFORMAT_RSA_... */
			u8 *e;
			size_t e_len;	/* Length of exponent in bit */
			u8 *p;
			size_t p_len;
			u8 *q;
			size_t q_len;
			u8 *n;
			size_t n_len;
		} rsa;
		struct {
			u8 keyformat;	/* SC_OPENPGP_KEYFORMAT_EC_... */
			u8 *privateD;
			size_t privateD_len;
			u8 *ecpointQ;
			size_t ecpointQ_len;
			struct sc_object_id oid;
			u8 oid_len;
		} ec;
	} u;
	time_t creationtime;
} sc_cardctl_openpgp_keystore_info_t;

/*
 * SmartCard-HSM
 */
typedef struct sc_cardctl_sc_hsm_keygen_info {
	u8 key_id;
	u8 auth_key_id;				/* Key to use for CV request signing */
	u8 *gakprequest;			/* GENERATE ASYMMETRIC KEY PAIR request */
	size_t gakprequest_len;		/* Size of request */
	u8 *gakpresponse;			/* Authenticated CV request, allocated by the driver */
	size_t gakpresponse_len;	/* Size of response */
} sc_cardctl_sc_hsm_keygen_info_t;

typedef struct sc_cardctl_sc_hsm_init_param {
	u8 init_code[8];			/* Initialization code */
	u8 *user_pin;				/* Initial user PIN */
	size_t user_pin_len;		/* Length of user PIN */
	u8 user_pin_retry_counter;	/* Retry counter default value */
	struct sc_aid bio1;			/* AID of biometric server for template 1 */
	struct sc_aid bio2;			/* AID of biometric server for template 2 */
	u8 options[2];				/* Initialization options */
	signed char dkek_shares;	/* Number of DKEK shares, 0 for card generated, -1 for none */
	char *label;				/* Token label to be set in EF.TokenInfo (2F03) */
} sc_cardctl_sc_hsm_init_param_t;

typedef struct sc_cardctl_sc_hsm_dkek {
	int importShare;			/* True to import share, false to just query status */
	u8 dkek_share[32];			/* AES-256 DKEK share */
	u8 dkek_shares;				/* Total number of shares */
	u8 outstanding_shares;		/* Number of shares to be presented */
	u8 key_check_value[8];		/* Key check value for DKEK */
} sc_cardctl_sc_hsm_dkek_t;

typedef struct sc_cardctl_sc_hsm_wrapped_key {
	u8 key_id;					/* Key identifier */
	u8 *wrapped_key;			/* Binary wrapped key */
	size_t wrapped_key_length;	/* Length of key blob */
} sc_cardctl_sc_hsm_wrapped_key_t;

/*
 * isoApplet
 */

#define SC_ISOAPPLET_ALG_REF_RSA_GEN_2048 0xF3
#define SC_ISOAPPLET_ALG_REF_EC_GEN 0xEC

typedef struct sc_cardctl_isoApplet_ec_parameters {
	struct sc_lv_data prime;
	struct sc_lv_data coefficientA;
	struct sc_lv_data coefficientB;
	struct sc_lv_data basePointG;
	struct sc_lv_data order;
	struct sc_lv_data coFactor;
} sc_cardctl_isoApplet_ec_parameters_t;

typedef struct sc_cardctl_isoApplet_genkey {
	u8 algorithm_ref;			/* Algorithm reference sent to card */
	unsigned int priv_key_ref;	/* Private key reference sent to card */
	union {
		struct
		{
			struct sc_lv_data modulus;
			struct sc_lv_data exponent;
		} rsa;
		struct
		{
			sc_cardctl_isoApplet_ec_parameters_t params;
			struct sc_lv_data ecPointQ;
		} ec;
	} pubkey;
} sc_cardctl_isoApplet_genkey_t;

typedef struct sc_cardctl_isoApplet_import_key {
	u8 algorithm_ref;			/* Algorithm reference sent to card */
	unsigned int priv_key_ref;	/* Private key reference sent to card */
	union {
		struct
		{
			struct sc_lv_data p;
			struct sc_lv_data q;
			struct sc_lv_data iqmp;
			struct sc_lv_data dmp1;
			struct sc_lv_data dmq1;
		} rsa;
		struct
		{
			sc_cardctl_isoApplet_ec_parameters_t params;
			struct sc_lv_data privateD;
		} ec;
	} privkey;
} sc_cardctl_isoApplet_import_key_t;

/*
 * coolkey object returned from the card control interface
 */
typedef struct sc_cardctl_coolkey_object {
        sc_path_t path;
        unsigned long id;
        size_t length;
        u8  *data;
} sc_cardctl_coolkey_object_t;


/* data structure to pass attributes through the ctl interface */
typedef struct sc_cardctl_coolkey_attribute {
        const sc_cardctl_coolkey_object_t *object;
	unsigned long attribute_type;
        u8 attribute_data_type;
        size_t attribute_length;
        const u8 *attribute_value;
} sc_cardctl_coolkey_attribute_t;

#define SC_CARDCTL_COOLKEY_ATTR_TYPE_STRING 0
#define SC_CARDCTL_COOLKEY_ATTR_TYPE_ULONG 1

typedef struct sc_cardctl_coolkey_find_object {
	int type; /* in parameter */
	unsigned long find_id; /* in parameter */
	sc_cardctl_coolkey_attribute_t *coolkey_template; /* in parameter */
	int template_count;                       /* in parameter */
	sc_cardctl_coolkey_object_t *obj; /* out parameter */
} sc_cardctl_coolkey_find_object_t;

#define SC_CARDCTL_COOLKEY_FIND_BY_ID       0
#define SC_CARDCTL_COOLKEY_FIND_BY_TEMPLATE 1

#ifdef __cplusplus
}
#endif

#endif /* _OPENSC_CARDCTL_H */
