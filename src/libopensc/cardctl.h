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
 	/* NON STANDART  */
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
	select_next,
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
	struct sc_cardctl_myeid_data_obj {
		int     P1;
		int     P2;
		u8 *    Data;
		size_t  DataLen;
		int     LengthMax;
	};

	struct sc_cardctl_myeid_gen_store_key_info {
	int             op_type;
	unsigned int    mod_len;   
	unsigned char  *mod;
	unsigned int    pubexp_len;  
	unsigned char  *pubexp;
	unsigned int    primep_len;  
	unsigned char  *primep;
	unsigned int    primeq_len;  
	unsigned char  *primeq;
	unsigned int    dp1_len;  
	unsigned char  *dp1;
	unsigned int    dq1_len;  
	unsigned char  *dq1;
	unsigned int    invq_len;  
	unsigned char  *invq;
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
} sc_cardctl_piv_genkey_info_t;

#ifdef __cplusplus
}
#endif

#endif /* _OPENSC_CARDCTL_H */
