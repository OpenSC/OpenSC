/*
 * card_ctl command numbers
 *
 * There is a range of generic card_ctls, and card-specific
 * ranges. I've used a 3-letter abbreviation of the card in
 * the prefix, but that's just a fad :)
 *
 * For now, I've reserved these:
 * 	0x0000xxxx	generic
 * 	0x4C4658xx	Cryptoflex
 * 	0x47504Bxx	GPK
 *      0x544353xx      TCOS
 */

#ifndef _OPENSC_CARDCTL_H
#define _OPENSC_CARDCTL_H

#include <opensc/types.h>

#ifdef  __cplusplus
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
	 * eToken specific calls
	 */
	SC_CARDCTL_ETOKEN_BASE = _CTL_PREFIX('E', 'T', 'K'),
	SC_CARDCTL_ETOKEN_PUT_DATA_FCI,
	SC_CARDCTL_ETOKEN_PUT_DATA_OCI,
	SC_CARDCTL_ETOKEN_PUT_DATA_SECI,
	SC_CARDCTL_ETOKEN_GENERATE_KEY,

	/*
	 * Starcos specific calls
	 */
	SC_CARDCTL_STARCOS_BASE = _CTL_PREFIX('S', 'T', 'A'),
	/* some Starcos SPK 2.3 specific commands */
	SC_CARDCTL_STARCOS_CREATE_FILE,
	SC_CARDCTL_STARCOS_CREATE_END,
	SC_CARDCTL_STARCOS_WRITE_KEY,
	SC_CARDCTL_STARCOS_GENERATE_KEY,

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
};

enum {
	SC_CARDCTRL_LIFECYCLE_ADMIN,
	SC_CARDCTRL_LIFECYCLE_USER,
	SC_CARDCTRL_LIFECYCLE_OTHER,
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
	SC_CARDCTL_MIOCOS_AC_SMARTPIN,
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
 * eToken PIN info
 */
struct sc_cardctl_etoken_obj_info {
	u8 *		data;
	size_t		len;
};

struct sc_cardctl_etoken_genkey_info {
	u8 *		random_data;
	size_t		random_len;
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
};

struct sc_cardctl_oberthur_genkey_info {
	unsigned int    id_prv, id_pub;
	unsigned int    key_bits;
	unsigned long   exponent;
	unsigned char * pubkey;
	unsigned int    pubkey_len;
};
	  
struct sc_cardctl_oberthur_updatekey_info {
	enum SC_CARDCTL_OBERTHUR_KEY_TYPE  type;
	unsigned int    component;
	unsigned char 	*data;
	unsigned int    len;
};

struct sc_cardctl_oberthur_createpin_info {
	unsigned int type;
	unsigned int ref;
	unsigned char *pin;
	unsigned int pin_len;
	unsigned int pin_tries;
	unsigned char *puk;
	unsigned int puk_len;
	unsigned int puk_tries;
};
	  
#ifdef  __cplusplus
}
#endif

#endif /* _OPENSC_CARDCTL_H */

