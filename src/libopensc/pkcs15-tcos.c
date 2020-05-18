/*
 * PKCS15 emulation layer for TCOS based preformatted cards
 *
 * Copyright (C) 2011, Peter Koch <pk@opensc-project.org>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "common/compat_strlcpy.h"
#include "common/compat_strlcat.h"
#include "internal.h"
#include "pkcs15.h"
#include "cardctl.h"
#include "log.h"

static int insert_cert(
	sc_pkcs15_card_t *p15card,
	const char       *path,
	unsigned char     id,
	int               writable,
	const char       *label
){
	sc_card_t *card=p15card->card;
	sc_context_t *ctx=p15card->card->ctx;
	struct sc_pkcs15_cert_info cert_info;
	struct sc_pkcs15_object cert_obj;
	unsigned char cert[20];
	int r;

	memset(&cert_info, 0, sizeof(cert_info));
	cert_info.id.len      = 1;
	cert_info.id.value[0] = id;
	cert_info.authority   = 0;
	sc_format_path(path, &cert_info.path);

	memset(&cert_obj, 0, sizeof(cert_obj));
	strlcpy(cert_obj.label, label, sizeof(cert_obj.label));
	cert_obj.flags = writable ? SC_PKCS15_CO_FLAG_MODIFIABLE : 0;

	if(sc_select_file(card, &cert_info.path, NULL)!=SC_SUCCESS){
		sc_log(ctx, 
			"Select(%s) failed\n", path);
		return 1;
	}
	if(sc_read_binary(card, 0, cert, sizeof(cert), 0)<0){
		sc_log(ctx, 
			"ReadBinary(%s) failed\n", path);
		return 2;
	}
	if(cert[0]!=0x30 || cert[1]!=0x82){
		sc_log(ctx, 
			"Invalid Cert: %02X:%02X:...\n", cert[0], cert[1]);
		return 3;
	}

	/* some certificates are prefixed by an OID */
	if(cert[4]==0x06 && cert[5]<10 && cert[6+cert[5]]==0x30 && cert[7+cert[5]]==0x82){
		cert_info.path.index=6+cert[5];
		cert_info.path.count=(cert[8+cert[5]]<<8) + cert[9+cert[5]] + 4;
	} else {
		cert_info.path.index=0;
		cert_info.path.count=(cert[2]<<8) + cert[3] + 4;
	}

	r=sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
	if(r!=SC_SUCCESS){
		sc_log(ctx,  "sc_pkcs15emu_add_x509_cert(%s) failed\n", path);
		return 4;
	}
	sc_log(ctx,  "%s: OK, Index=%d, Count=%d\n", path, cert_info.path.index, cert_info.path.count);
	return 0;
}

static int insert_key(
	sc_pkcs15_card_t *p15card,
	const char       *path,
	unsigned char     id,
	unsigned char     key_reference,
	int               key_length,
	unsigned char     auth_id,
	const char       *label
){
	sc_card_t *card=p15card->card;
	sc_context_t *ctx=p15card->card->ctx;
	sc_file_t *f;
	struct sc_pkcs15_prkey_info prkey_info;
	struct sc_pkcs15_object prkey_obj;
	int r, can_sign, can_crypt;

	memset(&prkey_info, 0, sizeof(prkey_info));
	prkey_info.id.len         = 1;
	prkey_info.id.value[0]    = id;
	prkey_info.native         = 1;
	prkey_info.key_reference  = key_reference;
	prkey_info.modulus_length = key_length;
	sc_format_path(path, &prkey_info.path);

	memset(&prkey_obj, 0, sizeof(prkey_obj));
	strlcpy(prkey_obj.label, label, sizeof(prkey_obj.label));
	prkey_obj.flags            = SC_PKCS15_CO_FLAG_PRIVATE;
	prkey_obj.auth_id.len      = 1;
	prkey_obj.auth_id.value[0] = auth_id;

	can_sign=can_crypt=0;
	if(card->type==SC_CARD_TYPE_TCOS_V3){
		unsigned char buf[256];
		int i, rec_no=0;
		if(prkey_info.path.len>=2) prkey_info.path.len-=2;
		sc_append_file_id(&prkey_info.path, 0x5349);
		if(sc_select_file(card, &prkey_info.path, NULL)!=SC_SUCCESS){
			sc_log(ctx, 
				"Select(%s) failed\n",
				sc_print_path(&prkey_info.path));
			return 1;
		}
		sc_log(ctx, 
			"Searching for Key-Ref %02X\n", key_reference);
		while((r=sc_read_record(card, ++rec_no, buf, sizeof(buf), SC_RECORD_BY_REC_NR))>0){
			int found=0;
			if(buf[0]!=0xA0) continue;
			for(i=2;i<buf[1]+2;i+=2+buf[i+1]){
				if(buf[i]==0x83 && buf[i+1]==1 && buf[i+2]==key_reference) ++found;
			}
			if(found) break;
		}
		if(r<=0){
			sc_log(ctx, "No EF_KEYD-Record found\n");
			return 1;
		}
		for(i=0;i<r;i+=2+buf[i+1]){
			if(buf[i]==0xB6) can_sign++;
			if(buf[i]==0xB8) can_crypt++;
		}
	} else {
		if(sc_select_file(card, &prkey_info.path, &f)!=SC_SUCCESS
			   	|| !f->prop_attr || f->prop_attr_len < 2){
			sc_log(ctx, 
				"Select(%s) failed\n",
				sc_print_path(&prkey_info.path));
			sc_file_free(f);
			return 1;
		}
		if (f->prop_attr[1] & 0x04) can_crypt=1;
		if (f->prop_attr[1] & 0x08) can_sign=1;
		sc_file_free(f);
	}
	prkey_info.usage= SC_PKCS15_PRKEY_USAGE_SIGN;
	if(can_crypt) prkey_info.usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT|SC_PKCS15_PRKEY_USAGE_DECRYPT;
	if(can_sign) prkey_info.usage |= SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;

	r=sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
	if(r!=SC_SUCCESS){
		sc_log(ctx,  "sc_pkcs15emu_add_rsa_prkey(%s) failed\n", path);
		return 4;
	}
	sc_log(ctx,  "%s: OK%s%s\n", path, can_sign ? ", Sign" : "", can_crypt ? ", Crypt" : "");
	return 0;
}

static int insert_pin(
	sc_pkcs15_card_t *p15card,
	const char       *path,
	unsigned char     id,
	unsigned char     auth_id,
	unsigned char     pin_reference,
	int               min_length,
	const char       *label,
	int               pin_flags
){
	sc_card_t *card=p15card->card;
	sc_context_t *ctx=p15card->card->ctx;
	sc_file_t *f;
	struct sc_pkcs15_auth_info pin_info;
	struct sc_pkcs15_object pin_obj;
	int r;

	memset(&pin_info, 0, sizeof(pin_info));
	pin_info.auth_id.len      = 1;
	pin_info.auth_id.value[0] = id;
	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin_info.attrs.pin.reference        = pin_reference;
	pin_info.attrs.pin.flags            = pin_flags;
	pin_info.attrs.pin.type             = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	pin_info.attrs.pin.min_length       = min_length;
	pin_info.attrs.pin.stored_length    = 16;
	pin_info.attrs.pin.max_length       = 16;
	pin_info.attrs.pin.pad_char         = '\0';
	pin_info.logged_in = SC_PIN_STATE_UNKNOWN;
	sc_format_path(path, &pin_info.path);

	memset(&pin_obj, 0, sizeof(pin_obj));
	strlcpy(pin_obj.label, label, sizeof(pin_obj.label));
	pin_obj.flags            = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;
	pin_obj.auth_id.len      = auth_id ? 0 : 1;
	pin_obj.auth_id.value[0] = auth_id;

	if(card->type==SC_CARD_TYPE_TCOS_V3){
		unsigned char buf[256];
		int i, rec_no=0;
		if(pin_info.path.len>=2) pin_info.path.len-=2;
		sc_append_file_id(&pin_info.path, 0x5049);
		if(sc_select_file(card, &pin_info.path, NULL)!=SC_SUCCESS){
			sc_log(ctx, 
				"Select(%s) failed\n",
				sc_print_path(&pin_info.path));
			return 1;
		}
		sc_log(ctx, 
			"Searching for PIN-Ref %02X\n", pin_reference);
		while((r=sc_read_record(card, ++rec_no, buf, sizeof(buf), SC_RECORD_BY_REC_NR))>0){
			int found=0, fbz=-1;
			if(buf[0]!=0xA0) continue;
			for(i=2;i<buf[1]+2;i+=2+buf[i+1]){
				if(buf[i]==0x83 && buf[i+1]==1 && buf[i+2]==pin_reference) ++found;
				if(buf[i]==0x90) fbz=buf[i+1+buf[i+1]];
			}
			if(found) pin_info.tries_left=fbz;
			if(found) break;
		}
		if(r<=0){
			sc_log(ctx, "No EF_PWDD-Record found\n");
			return 1;
		}
	} else {
		if(sc_select_file(card, &pin_info.path, &f)!=SC_SUCCESS
			   	|| !f->prop_attr || f->prop_attr_len < 4){
			sc_log(ctx, "Select(%s) failed\n", path);
			return 1;
		}
		pin_info.tries_left=f->prop_attr[3];
		sc_file_free(f);
	}

	r=sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
	if(r!=SC_SUCCESS){
		sc_log(ctx,  "sc_pkcs15emu_add_pin_obj(%s) failed\n", path);
		return 4;
	}
	sc_log(ctx,  "%s: OK, FBZ=%d\n", path, pin_info.tries_left);
	return 0;
}

static char *dirpath(char *dir, const char *path){
	static char buf[SC_MAX_PATH_STRING_SIZE];

	strlcpy(buf,dir,sizeof buf);
	strlcat(buf,path,sizeof buf);
	return buf;
}

static int detect_netkey(
	sc_pkcs15_card_t *p15card
){
	sc_card_t *card=p15card->card;
	sc_path_t p;
	sc_file_t *f;
	int keylen;
	char dir[10];
	const char *c_auth;

	/* NKS-Applikation ? */
	memset(&p, 0, sizeof(sc_path_t));
	p.type=SC_PATH_TYPE_DF_NAME;
	memcpy(p.value, "\xD2\x76\x00\x00\x03\x01\x02", p.len=7);
	if (sc_select_file(card,&p,&f)!=SC_SUCCESS) return 1;
	sprintf(dir,"%04X", f->id);
	sc_file_free(f);

	p15card->tokeninfo->manufacturer_id = strdup("TeleSec GmbH");
	p15card->tokeninfo->label = strdup(card->type==SC_CARD_TYPE_TCOS_V3 ? "NetKey V3 Card" : "NetKey Card");
	keylen= card->type==SC_CARD_TYPE_TCOS_V3 ? 2048 : 1024;
	c_auth= card->type==SC_CARD_TYPE_TCOS_V3 ? "C500" : "C100";

	insert_cert(p15card, dirpath(dir,"4331"), 0x45, 1, "Signatur Zertifikat 1");
	insert_cert(p15card, dirpath(dir,"4332"), 0x45, 1, "Signatur Zertifikat 2");
	insert_cert(p15card, dirpath(dir,"C000"), 0x45, 0, "Telesec Signatur Zertifikat");
	insert_cert(p15card, dirpath(dir,"43B1"), 0x46, 1, "Verschluesselungs Zertifikat 1");
	insert_cert(p15card, dirpath(dir,"43B2"), 0x46, 1, "Verschluesselungs Zertifikat 2");
	insert_cert(p15card, dirpath(dir,"C200"), 0x46, 0, "Telesec Verschluesselungs Zertifikat");
	insert_cert(p15card, dirpath(dir,"4371"), 0x47, 1, "Authentifizierungs Zertifikat 1");
	insert_cert(p15card, dirpath(dir,"4372"), 0x47, 1, "Authentifizierungs Zertifikat 2");
	insert_cert(p15card, dirpath(dir,c_auth), 0x47, 0, "Telesec Authentifizierungs Zertifikat");
	insert_cert(p15card, dirpath(dir,"C201"), 0x48, 0, "Telesec 1024bit Zertifikat");

	insert_key(p15card, dirpath(dir,"5331"), 0x45, 0x80, keylen, 4, "Signatur Schluessel");
	insert_key(p15card, dirpath(dir,"53B1"), 0x46, 0x81, keylen, 3, "Verschluesselungs Schluessel");
	insert_key(p15card, dirpath(dir,"5371"), 0x47, 0x82, keylen, 3, "Authentifizierungs Schluessel");
	insert_key(p15card, dirpath(dir,"0000"), 0x48, 0x83, 1024,   3, "1024bit Schluessel");

	insert_pin(p15card, "5000", 1, 2, 0x00, 6, "PIN",
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED
	);
	insert_pin(p15card, "5001", 2, 0, 0x01, 8, "PUK",
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED |
		SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_SO_PIN
	);
	if(card->type==SC_CARD_TYPE_TCOS_V3){
		insert_pin(p15card, dirpath(dir,"0000"), 3, 1, 0x83, 6, "NetKey PIN2",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
			SC_PKCS15_PIN_FLAG_INITIALIZED
		);
	} else {
		insert_pin(p15card, dirpath(dir,"5080"), 3, 1, 0x80, 6, "NetKey PIN0",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
			SC_PKCS15_PIN_FLAG_INITIALIZED
		);
	}
	insert_pin(p15card, dirpath(dir,"5081"), 4, 1, 0x81, 6, "NetKey PIN1",
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
		SC_PKCS15_PIN_FLAG_INITIALIZED
	);

	/* SigG-Applikation */
	p.len=7; p.type=SC_PATH_TYPE_DF_NAME;
	memcpy(p.value, "\xD2\x76\x00\x00\x66\x01", p.len=6);
	if (sc_select_file(card,&p,&f)==SC_SUCCESS){
		sprintf(dir,"%04X", f->id);
		sc_file_free(f);

		insert_cert(p15card, dirpath(dir,"C000"), 0x49, 1, "SigG Zertifikat 1");
		insert_cert(p15card, dirpath(dir,"4331"), 0x49, 1, "SigG Zertifikat 2");
		insert_cert(p15card, dirpath(dir,"4332"), 0x49, 1, "SigG Zertifikat 3");
		
		if(card->type==SC_CARD_TYPE_TCOS_V3){
			insert_key(p15card, dirpath(dir,"0000"), 0x49, 0x84, 2048, 5, "SigG Schluessel");
		} else {
			insert_key(p15card, dirpath(dir,"5331"), 0x49, 0x80, 1024, 5, "SigG Schluessel");
		}

		insert_pin(p15card, dirpath(dir,"5081"), 5, 0, 0x81, 6, "SigG PIN",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
			SC_PKCS15_PIN_FLAG_INITIALIZED
		);
		if(card->type==SC_CARD_TYPE_TCOS_V3){
			insert_pin(p15card, dirpath(dir,"0000"), 6, 0, 0x83, 8, "SigG PIN2",
				SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
				SC_PKCS15_PIN_FLAG_INITIALIZED
			);
		}
	}

	return 0;
}

static int detect_idkey(
	sc_pkcs15_card_t *p15card
){
	sc_card_t *card=p15card->card;
	sc_path_t p;

	/* TCKEY-Applikation ? */
	memset(&p, 0, sizeof(sc_path_t));
	p.type=SC_PATH_TYPE_DF_NAME;
	memcpy(p.value, "\xD2\x76\x00\x00\x03\x0C\x01", p.len=7);
	if (sc_select_file(card,&p,NULL)!=SC_SUCCESS) return 1;

	p15card->tokeninfo->manufacturer_id = strdup("TeleSec GmbH");
	p15card->tokeninfo->label = strdup("IDKey Card");

	insert_cert(p15card, "DF074331", 0x45, 1, "Signatur Zertifikat 1");
	insert_cert(p15card, "DF074332", 0x46, 1, "Signatur Zertifikat 2");
	insert_cert(p15card, "DF074333", 0x47, 1, "Signatur Zertifikat 3");
	insert_cert(p15card, "DF084331", 0x4B, 1, "Verschluesselungs Zertifikat 1");
	/* TODO should others come here too? */

	insert_key(p15card, "DF074E03", 0x45, 0x84, 2048, 1, "IDKey1");
	insert_key(p15card, "DF074E04", 0x46, 0x85, 2048, 1, "IDKey2");
	insert_key(p15card, "DF074E05", 0x47, 0x86, 2048, 1, "IDKey3");
	insert_key(p15card, "DF074E06", 0x48, 0x87, 2048, 1, "IDKey4");
	insert_key(p15card, "DF074E07", 0x49, 0x88, 2048, 1, "IDKey5");
	insert_key(p15card, "DF074E08", 0x4A, 0x89, 2048, 1, "IDKey6");
	insert_key(p15card, "DF084E01", 0x4B, 0x81, 2048, 1, "IDKey7");

	insert_pin(p15card, "5000", 1, 2, 0x00, 6, "PIN",
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED
	);
	insert_pin(p15card, "5001", 2, 0, 0x01, 8, "PUK",
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED |
		SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_SO_PIN
	);

	return 0;
}

static int detect_signtrust(
	sc_pkcs15_card_t *p15card
){
	if(insert_cert(p15card,"8000DF01C000", 0x45, 1, "Signatur Zertifikat")) return 1;
	p15card->tokeninfo->manufacturer_id = strdup("Deutsche Post");
	p15card->tokeninfo->label = strdup("SignTrust Card");

	insert_cert(p15card,"800082008220", 0x46, 1, "Verschluesselungs Zertifikat");
	insert_cert(p15card,"800083008320", 0x47, 1, "Authentifizierungs Zertifikat");

	insert_key(p15card,"8000DF015331", 0x45, 0x80, 1024, 1, "Signatur Schluessel");
	insert_key(p15card,"800082008210", 0x46, 0x80, 1024, 2, "Verschluesselungs Schluessel");
	insert_key(p15card,"800083008310", 0x47, 0x80, 1024, 3, "Authentifizierungs Schluessel");

	insert_pin(p15card,"8000DF010000", 1, 0, 0x81, 6, "Signatur PIN",
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
		SC_PKCS15_PIN_FLAG_INITIALIZED
	);
	insert_pin(p15card,"800082000040", 2, 0, 0x81, 6, "Verschluesselungs PIN",
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
		SC_PKCS15_PIN_FLAG_INITIALIZED
	);
	insert_pin(p15card,"800083000040", 3, 0, 0x81, 6, "Authentifizierungs PIN",
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
		SC_PKCS15_PIN_FLAG_INITIALIZED
	);

	return 0;
}

static int detect_datev(
	sc_pkcs15_card_t *p15card
){
	if(insert_cert(p15card,"3000C500", 0x45, 0, "Signatur Zertifikat")) return 1;
	p15card->tokeninfo->manufacturer_id = strdup("DATEV");
	p15card->tokeninfo->label = strdup("DATEV Classic");

	insert_cert(p15card,"DF02C200", 0x46, 0, "Verschluesselungs Zertifikat");
	insert_cert(p15card,"DF02C500", 0x47, 0, "Authentifizierungs Zertifikat");

	insert_key(p15card,"30005371", 0x45, 0x82, 1024, 1, "Signatur Schluessel");
	insert_key(p15card,"DF0253B1", 0x46, 0x81, 1024, 1, "Verschluesselungs Schluessel");
	insert_key(p15card,"DF025371", 0x47, 0x82, 1024, 1, "Authentifizierungs Schluessel");

	insert_pin(p15card,"5001", 1, 0, 0x01, 6, "PIN",
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED
	);

	return 0;
}

static int detect_unicard(
	sc_pkcs15_card_t *p15card
){
	if(!insert_cert(p15card,"41004352", 0x45, 1, "Zertifikat 1")){
		p15card->tokeninfo->manufacturer_id = strdup("JLU Giessen");
		p15card->tokeninfo->label = strdup("JLU Giessen Card");

		insert_cert(p15card,"41004353", 0x46, 1, "Zertifikat 2");
		insert_cert(p15card,"41004354", 0x47, 1, "Zertifikat 3");
		insert_key(p15card,"41005103", 0x45, 0x83, 1024, 1, "Schluessel 1");
		insert_key(p15card,"41005104", 0x46, 0x84, 1024, 1, "Schluessel 2");
		insert_key(p15card,"41005105", 0x47, 0x85, 1024, 1, "Schluessel 3");

	} else if(!insert_cert(p15card,"41014352", 0x45, 1, "Zertifikat 1")){
		p15card->tokeninfo->manufacturer_id = strdup("TU Darmstadt");
		p15card->tokeninfo->label = strdup("TUD Card");

		insert_cert(p15card,"41014353", 0x46, 1, "Zertifikat 2");
		insert_cert(p15card,"41014354", 0x47, 1, "Zertifikat 3");
		insert_key(p15card,"41015103", 0x45, 0x83, 1024, 1, "Schluessel 1");
		insert_key(p15card,"41015104", 0x46, 0x84, 1024, 1, "Schluessel 2");
		insert_key(p15card,"41015105", 0x47, 0x85, 1024, 1, "Schluessel 3");

	} else return 1;

	insert_pin(p15card,"5000", 1, 2, 0x00, 6, "PIN",
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED
	);
	insert_pin(p15card,"5008", 2, 0, 0x01, 8, "PUK",
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED |
		SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_SO_PIN
	);

	return 0;
}

int sc_pkcs15emu_tcos_init_ex(
	sc_pkcs15_card_t   *p15card,
	struct sc_aid *aid
){
	sc_card_t         *card = p15card->card;
	sc_context_t      *ctx = p15card->card->ctx;
	sc_serial_number_t serialnr;
	char               serial[30];
	int r;

	/* check if we have the correct card OS unless SC_PKCS15EMU_FLAGS_NO_CHECK */
	if (card->type!=SC_CARD_TYPE_TCOS_V2 && card->type!=SC_CARD_TYPE_TCOS_V3) return SC_ERROR_WRONG_CARD;

	/* get the card serial number */
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serialnr);
	if (r < 0) {
		sc_log(ctx,  "unable to get ICCSN\n");
		return SC_ERROR_WRONG_CARD;
	}
	sc_bin_to_hex(serialnr.value, serialnr.len , serial, sizeof(serial), 0);
	serial[19] = '\0';
	p15card->tokeninfo->serial_number = strdup(serial);

	if(!detect_netkey(p15card)) return SC_SUCCESS;
	if(!detect_idkey(p15card)) return SC_SUCCESS;
	if(!detect_unicard(p15card)) return SC_SUCCESS;
	if(!detect_signtrust(p15card)) return SC_SUCCESS;
	if(!detect_datev(p15card)) return SC_SUCCESS;

	return SC_ERROR_INTERNAL;
}
