#ifndef _OPENSC_CARD_OBERTHUR_H
#define _OPENSC_CARD_OBERTHUR_H

#include <opensc/opensc.h>

#define AID_OBERTHUR_V2 0x201
#define AID_OBERTHUR_V4 0x401
#define AID_OBERTHUR_V5 0x501

#define ATR_OBERTHUR		0x0100
#define ATR_OBERTHUR_32K	0x0110
#define ATR_OBERTHUR_32K_BIO	0x0112
#define ATR_OBERTHUR_64K	0x0120

#define FLAG_KEYGEN	 0x0001

#define AUTH_PIN 	1
#define AUTH_PUK	2

#define PUBKEY_512_ASN1_SIZE 	0x4A
#define PUBKEY_1024_ASN1_SIZE 	0x8C
#define PUBKEY_2048_ASN1_SIZE 	0x10E

#define SC_OBERTHUR_MAX_ATTR_SIZE 8

struct NTLV {
	char *name;
	unsigned int tag;
	int len;
	unsigned char *value;
};
typedef struct NTLV NTLV_t;

struct oberthur_atr {
	const char *atr;
	const char *name;
	unsigned int	type;
};

struct oberthur_aid {
	const char *aid;
	const char *name;
	unsigned int type;
};
typedef struct oberthur_aid oberthur_aid_t;
	
struct auth_application_id {
	unsigned int tag;
	u8 value[SC_MAX_AID_SIZE];
	int len;
};
typedef struct auth_application_id auth_application_id_t;

struct auth_senv {
	unsigned int algorithm;
	int key_file_id;
	size_t key_size;
};
typedef struct auth_senv auth_senv_t;


struct auth_private_data {
	struct sc_pin_cmd_pin pin_info;
	long int sn;
	auth_application_id_t aid;
	auth_senv_t senv;
};
typedef struct auth_private_data auth_private_data_t;

#endif /* _OPENSC_CARD_OBERTHUR_H */
