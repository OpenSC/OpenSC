/*
 * card-piv.c: Support for PIV-II from NIST SP800-73 
 * card-default.c: Support for cards with no driver
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2005,2006,2007 Douglas E. Engert <deengert@anl.gov>
 * Copyright (C) 2006, Identity Alliance, Thomas Harning <thomas.harning@identityalliance.com>
 * Copyright (C) 2007, EMC, Russell Larner <rlarner@rsa.com>
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

#include "internal.h"

#ifdef ENABLE_OPENSSL

#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "asn1.h"
#include "cardctl.h"
#ifdef ENABLE_ZLIB
#include "compression.h"
#endif

enum {
	PIV_OBJ_CCC = 0,
	PIV_OBJ_CHUI,
	PIV_OBJ_UCHUI,  /* new with 800-73-2 */
	PIV_OBJ_X509_PIV_AUTH,
	PIV_OBJ_CHF,
	PIV_OBJ_PI,
	PIV_OBJ_CHFI,
	PIV_OBJ_X509_DS,
	PIV_OBJ_X509_KM,
	PIV_OBJ_X509_CARD_AUTH,
	PIV_OBJ_SEC_OBJ,
	PIV_OBJ_9B03,
	PIV_OBJ_9A06,
	PIV_OBJ_9C06,
	PIV_OBJ_9D06,
	PIV_OBJ_9E06,
	PIV_OBJ_LAST_ENUM
};

/* flags in the piv_obj_cache */

#define PIV_OBJ_CACHE_VALID         1

typedef struct piv_obj_cache {
	u8* obj_data;
	size_t obj_len;
	u8* internal_obj_data; /* like a cert in the object */
	size_t internal_obj_len;
	int flags;
} piv_obj_cache_t;

typedef struct piv_private_data {
	struct sc_pin_cmd_pin pin_info;
	sc_file_t *aid_file;
	int enumtag;
	int  selected_obj; /* The index into the piv_objects last selected */
	int  return_only_cert; /* return the cert from the object */
	int  rb_state; /* first time -1, 0, in middle, 1 at eof */
	size_t max_recv_size; /* saved size, need to lie to pkcs15_read_file */
	size_t max_send_size; 
	int key_ref; /* saved from set_security_env and */
	int alg_id;  /* used in decrypt, signature */ 
	piv_obj_cache_t obj_cache[PIV_OBJ_LAST_ENUM];
} piv_private_data_t;

#define PIV_DATA(card) ((piv_private_data_t*)card->drv_data)

struct piv_aid {
	int enumtag;
	size_t len_short;	/* min lenght without version */
	size_t len_long;	/* With version and other stuff */
	u8 *value;
};
 
/* The Generic entry should be the "A0 00 00 03 08 00 00 01 00 "
 * NIST published  this on 10/6/2005   
 * 800-73-2 is due for release 11/2007. 
 * 800-73-2 Part 1 now refers to version "02 00"
 * i.e. "A0 00 00 03 08 00 00 01 00 02 00". 
 * but we dont need the version number. but could get it from the PIX. 
 */ 
static struct piv_aid piv_aids[] = {
	{SC_CARD_TYPE_PIV_II_GENERIC, 
		 9, 9, (u8 *) "\xA0\x00\x00\x03\x08\x00\x00\x10\x00" },
	{0,  9, 0, NULL }
};

/* flags in the piv_object */

#define PIV_OBJECT_TYPE_CERT		1
#define PIV_OBJECT_TYPE_PUBKEY		2

struct piv_object {
	int enumtag;
	const char * name;
	const char * oidstring;
	size_t tag_len;
	u8  tag_value[3];
	u8  containerid[2];	/* will use as relative paths for simulation */
	int flags;              /* object has some internal object like a cert */
};

/* Must be in order, and one per enumerated PIV_OBJ */
static struct piv_object piv_objects[] = { 
	{ PIV_OBJ_CCC, "Card Capability Container", 
			"2.16.840.1.101.3.7.1.219.0", 3, "\x5F\xC1\x07", "\xDB\x00", 0},
	{ PIV_OBJ_CHUI, "Card Holder Unique Identifier", 
			"2.16.840.1.101.3.7.2.48.0", 3, "\x5F\xC1\x02", "\x30\x00", 0},
	{ PIV_OBJ_UCHUI, "Unsigned Card Holder Unique Identifier", 
			"2.16.840.1.101.3.7.2.48.1", 3, "\x5F\xC1\x04", "\x30\x10",  0}, 
	{ PIV_OBJ_X509_PIV_AUTH, "X.509 Certificate for PIV Authentication", 
			"2.16.840.1.101.3.7.2.1.1", 3, "\x5F\xC1\x05", "\x01\x01", PIV_OBJECT_TYPE_CERT} , 
		/* extra 400 is hack for MultOS card which returns 2200 bytes  */
	{ PIV_OBJ_CHF, "Card Holder Fingerprints",
			"2.16.840.1.101.3.7.2.96.16", 3, "\x5F\xC1\x03", "\x60\x10", 0},
	{ PIV_OBJ_PI, "Printed Information", 
			"2.16.840.1.101.3.7.2.48.1", 3, "\x5F\xC1\x09", "\x30\x01", 0},
	{ PIV_OBJ_CHFI, "Card Holder Facial Image",
			"2.16.840.1.101.3.7.2.96.48", 3, "\x5F\xC1\x08", "\x60\x30", 0},
	{ PIV_OBJ_X509_DS, "X.509 Certificate for Digital Signature",
			"2.16.840.1.101.3.7.2.1.0", 3, "\x5F\xC1\x0A", "\x01\x00", PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_X509_KM, "X.509 Certificate for Key Management",
			"2.16.840.1.101.3.7.2.1.2", 3, "\x5F\xC1\x0B", "\x01\x02", PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_X509_CARD_AUTH, "X.509 Certificate for Card Authentication",
			"2.16.840.1.101.3.7.2.5.0", 3, "\x5F\xC1\x01", "\x05\x00", PIV_OBJECT_TYPE_CERT}, 
	{ PIV_OBJ_SEC_OBJ, "Security Object", 
			"2.16.840.1.101.3.7.2.144.0", 3, "\x5F\xC1\x06", "\x90\x00", 0}, 
/* following not standard , to be used by piv-tool only for testing */
	{ PIV_OBJ_9B03, "3DES-ECB ADM", 
			"2.16.840.1.101.3.7.2.9999.3", 2, "\x9B\x03", "\x9B\x03", 0},
	/* Only used when signing a cert req, usually from engine
	 * after piv-tool generated the key and saved the pub key 
	 * to a file. Note RSA key can be 1024, 2048 or 3072 
	 * but still use the "9x06" name.
	 */
	{ PIV_OBJ_9A06, "RSA 9A Pub key from last genkey",
			"2.16.840.1.101.3.7.2.9999.20", 2, "\x9A\x06", "\x9A\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9C06, "Pub 9C key from last genkey",
			"2.16.840.1.101.3.7.2.9999.21", 2, "\x9C\x06", "\x9C\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9D06, "Pub 9D key from last genkey",
			"2.16.840.1.101.3.7.2.9999.22", 2, "\x9D\x06", "\x9D\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9E06, "Pub 9E key from last genkey",
			"2.16.840.1.101.3.7.2.9999.23", 2, "\x9E\x06", "\x9E\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_LAST_ENUM, "", "", 0, "", "", 0}
};
	
static struct sc_card_operations piv_ops;

static struct sc_card_driver piv_drv = {
	"PIV-II  for multiple cards",
	"piv",
	&piv_ops,
	NULL, 0, NULL
};

/*
 * If ptr == NULL, just return the size of the tag and lenght and data
 * otherwise, store tag and length at **ptr, and increment
 */

static size_t put_tag_and_len(unsigned int tag, size_t len, u8 **ptr)
{
	int i;
	u8 *p;
	
	if (len < 128) { 
		i = 2;
	} else if (len < 256) { 
		i = 3;
	} else { 
		i = 4;
	}
	
	if (ptr) {
		p = *ptr;
		*p++ = (u8)tag;
		switch (i) {
			case 2:
				*p++ = len;
				break;
			case 3:
				*p++ = 0x81;
				*p++ = len;
				break;
			case 4:
				*p++ = 0x82;
				*p++ = (u8) (len >> 8);
				*p++ = (u8) (len & 0xff);
				break;
		}
		*ptr = p;
	} else {
		i += len;
	}
	return i;
}

/*
 * Send a command and receive data. There is always something to send. 
 * Used by  GET DATA, PUT DATA, GENERAL AUTHENTICATE 
 * and GENERATE ASYMMETRIC KEY PAIR.
 * GET DATA may call to get the first 128 bytes to get the lenght gfrom the tag. 
 *
 * A caller may provide a buffer, and length to read. If not provided,
 * an internal 4096 byte buffer is used, and a copy is returned to the
 * caller. that need to be freed by the caller.   
 */

static int piv_general_io(sc_card_t *card, int ins, int p1, int p2, 
	const u8 * sendbuf, size_t sendbuflen, u8 ** recvbuf,
	size_t * recvbuflen)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	sc_apdu_t apdu;
	u8 rbufinitbuf[4096]; 
	u8 *rbuf;
	size_t rbuflen;
	unsigned int cla_out, tag_out;
	const u8 *body;
	size_t bodylen;


	SC_FUNC_CALLED(card->ctx,1);
	
	sc_debug(card->ctx, "%02x %02x %02x %d : %d %d\n",
		 ins, p1, p2, sendbuflen , priv->max_send_size, priv->max_recv_size);

	rbuf = rbufinitbuf;
	rbuflen = sizeof(rbufinitbuf);

	/* if caller provided a buffer end length */
	if (recvbuf && *recvbuf && recvbuflen && *recvbuflen) {
		rbuf = *recvbuf;
		rbuflen = *recvbuflen;
	}

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		SC_FUNC_RETURN(card->ctx, 1, r);
		
	sc_format_apdu(card, &apdu, 
			recvbuf ? SC_APDU_CASE_4_SHORT: SC_APDU_CASE_3_SHORT, 
			ins, p1, p2);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	apdu.lc = sendbuflen;
	apdu.datalen = sendbuflen;
	apdu.data = sendbuf;

	if (recvbuf) {
		apdu.resp = rbuf;
		apdu.le = (priv->max_recv_size <= rbuflen)? priv->max_recv_size : rbuflen;
		apdu.resplen = rbuflen;
	} else {
		 apdu.resp =  rbuf;
		 apdu.le = 0;
		 apdu.resplen = 0;
	}

	/* TODO if read_binary is fixed, this is not needed */
	card->max_recv_size = priv->max_recv_size;

	sc_debug(card->ctx,"calling sc_transmit_apdu flags=%x le=%d, resplen=%d, resp=%p", 
		apdu.flags, apdu.le, apdu.resplen, apdu.resp);

	/* with new adpu.c and chaining, this actually reads the whole object */
	r = sc_transmit_apdu(card, &apdu);
	/* TODO if read_binary is fixed, this is not needed */
	card->max_recv_size = 0xffff;

	sc_debug(card->ctx,"DEE r=%d apdu.resplen=%d sw1=%02x sw2=%02x", 
			r, apdu.resplen, apdu.sw1, apdu.sw2);
	if (r < 0) {
		sc_debug(card->ctx,"Transmit failed");
		goto err;
	}
			
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	
/*TODO may be 6c nn if reading only the length */
/* TODO look later at tag vs size read too */
	if (r < 0) {
		sc_debug(card->ctx, "Card returned error ");
		goto err;
	}

	/*
	 * See how much we read and make sure it is asn1 
	 * if not, return 0 indicating no data found
	 */  

	
	rbuflen = 0;  /* in case rseplen < 3  i.e. not parseable */
	if ( recvbuflen && recvbuf && apdu.resplen > 3) {
		*recvbuflen = 0;
		/* we should have all the tag data, so we have to tell sc_asn1_find_tag 
		 * the buffer is bigger, so it will not produce "ASN1.tag too long!" */

		body = rbuf;
		if (sc_asn1_read_tag(&body, 0xffff, &cla_out, &tag_out, &bodylen) !=  SC_SUCCESS) 		{
			/* only early beta cards had this problem */
			sc_debug(card->ctx, "***** received buffer tag MISSING ");
			body = rbuf;
			/* some readers/cards might return 6c 00 */ 
			if (apdu.sw1 == 0x61  || apdu.sw2 == 0x6c ) 
				bodylen = 12000;
			else
				bodylen = apdu.resplen;
		}
		
		rbuflen = body - rbuf + bodylen;

		/* if using internal buffer, alloc new one */
		if (rbuf == rbufinitbuf) {
			*recvbuf = (u8 *)malloc(rbuflen); 
				sc_debug(card->ctx, "DEE got buffer %p len %d",*recvbuf,  rbuflen);
			if (*recvbuf == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto err;
			}

			memcpy(*recvbuf, rbuf, rbuflen); /* copy tag too */
		}
	} 

	if (recvbuflen) { 
		*recvbuflen =  rbuflen;
		r = *recvbuflen;
	}

err:
	sc_unlock(card);
	SC_FUNC_RETURN(card->ctx, 1, r);
}

/* Add the PIV-II operations */
/* Should use our own keydata, actually should be common to all cards */
/* only do RSA for now */

static int piv_generate_key(sc_card_t *card, 
		struct sc_cardctl_cryptoflex_genkey_info *keydata)
{
	int r;
	u8 *rbuf = NULL; 
	size_t rbuflen = 0;
	size_t buf_len = 0;
	u8 *buf_end;
	u8 *p, *rp, *tag;
	u8 tagbuf[16]; 
	u8 outdata[3]; /* we could also add tag 81 for exponent */
	size_t taglen, i;
	size_t out_len;
	size_t in_len;
	unsigned int cla_out, tag_out;
	
	SC_FUNC_CALLED(card->ctx, 1);

	keydata->exponent = 0;
	keydata->pubkey = NULL;
	keydata->pubkey_len = 0;

	
	out_len = 3;
	outdata[0] = 0x80;
	outdata[1] = 0x01;
	switch (keydata->key_bits) {
		case 1024: outdata[2] = 0x06; break;
		case 2048: outdata[2] = 0x07; break;
		case 3072: outdata[2] = 0x05; break;
		default:
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}

	p = tagbuf;

	put_tag_and_len(0xAC, out_len, &p);

	memcpy(p, outdata, out_len);
	p+=out_len;

	rp = rbuf;
	buf_end = rp + buf_len;

	r = piv_general_io(card, 0x47, 0x00, keydata->key_num, 
			tagbuf, p - tagbuf, &rbuf, &rbuflen);
	
	if (r >= 0) {
		const u8 *cp;
		keydata->exponent = 0;

		/* expected tag is 7f49.  */
		/* we will whatever tag is present */

		cp = rbuf;
		in_len = rbuflen;

		r = sc_asn1_read_tag(&cp, rbuflen, &cla_out, &tag_out, &in_len);
		if (r != SC_SUCCESS) {
			sc_debug(card->ctx,"Tag buffer not found");
			goto err;
		}
		
		tag = (u8 *) sc_asn1_find_tag(card->ctx, cp, in_len, 0x82, &taglen);
		if (tag != NULL && taglen <= 4) {
			keydata->exponent = 0;
			for (i = 0; i < taglen;i++) {
				keydata->exponent = (keydata->exponent<<8) + tag[i];
			}
		}
		tag = (u8 *) sc_asn1_find_tag(card->ctx, cp, in_len, 0x81, &taglen);
	
		if (tag != NULL && taglen > 0) {
			keydata->pubkey = malloc(taglen);
			if (keydata->pubkey == NULL)
				SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OUT_OF_MEMORY);
			keydata->pubkey_len = taglen;
			memcpy (keydata->pubkey, tag, taglen);
		}
	/* TODO could add key to cache so could use engine to generate key, and */
		r = 0;
	}
	
err:
	if (rbuf)
		free(rbuf);
	SC_FUNC_RETURN(card->ctx, 1, r);
}


static int piv_select_aid(sc_card_t* card, u8* aid, size_t aidlen, u8* response, size_t *responselen)
{
	sc_apdu_t apdu;
	int r;

	SC_FUNC_CALLED(card->ctx,4);
	if (card->ctx->debug >= 5)
		sc_debug(card->ctx, "Got args: aid=%x, aidlen=%d, response=%x, responselen=%d\n", aid, aidlen, response, *responselen);

	sc_format_apdu(card, &apdu, 
		response == NULL ? SC_APDU_CASE_3_SHORT : SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
	apdu.lc = aidlen;
	apdu.data = aid;
	apdu.datalen = aidlen;
	apdu.resp = response;
	apdu.resplen = *responselen;
	apdu.le = response == NULL ? 0 : 256; /* could be 21  for fci */

	r = sc_transmit_apdu(card, &apdu);
	*responselen = apdu.resplen;
	SC_TEST_RET(card->ctx, 4,  r);
	SC_FUNC_RETURN(card->ctx, 4,  sc_check_sw(card, apdu.sw1, apdu.sw2));
}

/* find the PIV AID on the card. If card->type already filled in,
 * then look for specific AID only
 * Assumes that priv may not be present
 */

static int piv_find_aid(sc_card_t * card, sc_file_t *aid_file)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r,i;
	u8 *tag;
	size_t taglen;
	u8 *pix;
	size_t pixlen;
	size_t resplen = sizeof(rbuf);

	SC_FUNC_CALLED(card->ctx,1);

	/* first  see if the default applcation will return a template
	 * that we know about. 
	 */

	if (card->type == SC_CARD_TYPE_PIV_II_GENERIC) 
		SC_FUNC_RETURN(card->ctx, 1, 0);

	r = piv_select_aid(card, piv_aids[0].value, piv_aids[0].len_short, rbuf, &resplen);
	if (r >= 0 && resplen > 2 ) {
		tag = (u8 *) sc_asn1_find_tag(card->ctx, rbuf, resplen, 0x61, &taglen);
		if (tag != NULL) {
			pix = (u8 *) sc_asn1_find_tag(card->ctx, tag, taglen, 0x4F, &pixlen);
			if (pix != NULL ) { 
				sc_debug(card->ctx,"found PIX");
		 
				/* early cards returned full AID, rather then just the pix */
				for (i = 0; piv_aids[i].len_long != 0; i++) {
					if ((pixlen >= 6 && memcmp(pix, piv_aids[i].value + 5, 
									piv_aids[i].len_long - 5 ) == 0)
						 || ((pixlen >=  piv_aids[i].len_short &&
							memcmp(pix, piv_aids[i].value,
							piv_aids[i].len_short) == 0))) {
						if (card->type > SC_CARD_TYPE_PIV_II_BASE &&
							card->type < SC_CARD_TYPE_PIV_II_BASE+1000 &&
							card->type == piv_aids[i].enumtag) {
							SC_FUNC_RETURN(card->ctx, 1, i);
						} else {
							SC_FUNC_RETURN(card->ctx, 1, i);
						}
					}
				}
			}
		}
	}

	/* for testing, we can force the use of a specific AID  
	 *  by using the card= parameter in conf file 
	 */
	for (i = 0; piv_aids[i].len_long != 0; i++) {
		if (card->type > SC_CARD_TYPE_PIV_II_BASE &&
			card->type < SC_CARD_TYPE_PIV_II_BASE+1000 &&
			card->type != piv_aids[i].enumtag) {
				continue;
		} 
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
		apdu.lc = piv_aids[i].len_long;
		apdu.data = piv_aids[i].value;
	
		apdu.datalen = apdu.lc;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 256;

		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, r, "APDU transmit failed");

		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	

		if (r)  {
			if (card->type != 0 && card->type == piv_aids[i].enumtag) {
				SC_FUNC_RETURN(card->ctx, 1, i);
			}
			continue; 
		}

		if ( apdu.resplen == 0 && r == 0) { 
			/* could be the MSU card */
			continue; /* other cards will return a FCI */
		}

		if (apdu.resp[0] != 0x6f || apdu.resp[1] > apdu.resplen - 2 ) 
			SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NO_CARD_SUPPORT);
	
		card->ops->process_fci(card, aid_file, apdu.resp+2, apdu.resp[1]);
		if (aid_file->name == NULL) 
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NO_CARD_SUPPORT);

		SC_FUNC_RETURN(card->ctx, 1, i);
	}
	
	SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NO_CARD_SUPPORT);
}


/* the tag is the PIV_OBJ_*  */
static int piv_get_data(sc_card_t * card, int enumtag, 
			u8 **buf, size_t *buf_len)
{
	piv_private_data_t * priv = PIV_DATA(card);
	u8 *p;
	int r = 0;
	u8 tagbuf[8];
	size_t tag_len;
	char * keyenvname = NULL;
	
	SC_FUNC_CALLED(card->ctx,1);
	sc_debug(card->ctx, "#%d \n", enumtag);

	//assert(enumtag >= 0 && enumtag < PIV_OBJ_LAST_ENUM);
	
	tag_len = piv_objects[enumtag].tag_len;

	p = tagbuf;
	put_tag_and_len(0x5c, tag_len, &p);
	memcpy(p, piv_objects[enumtag].tag_value, tag_len);
	p += tag_len;


	/*
	 * the PIV card will only recover the public key during a generate
	 * key operation. If the piv-tool was used it would save this
	 * as an OpenSSL EVP_KEY PEM using the -o parameter
	 * we will look to see if there is a file then load it
	 * this is ugly, and maybe the pkcs15 cache would work
	 * but we only need it to get the OpenSSL req with engine to work.
	 * Each of the 4 keys with certs has its own file. 
	 */

	switch (piv_objects[enumtag].enumtag) {
		case PIV_OBJ_9A06:
			keyenvname = "PIV_9A06_KEY";
			break;
		case PIV_OBJ_9C06:
			keyenvname = "PIV_9C06_KEY";
			break;
		case PIV_OBJ_9D06:
			keyenvname = "PIV_9D06_KEY";
			break;
		case PIV_OBJ_9E06:
			keyenvname = "PIV_9E06_KEY";
			break;
	}

	if (keyenvname)  {
		BIO * bp = NULL;
		RSA * rsa = NULL;
		u8 *q;
		size_t derlen;
		size_t taglen;
		char * keyfilename = NULL;

		keyfilename = getenv(keyenvname);

		if (keyfilename == NULL) {
			r = SC_ERROR_FILE_NOT_FOUND;
			goto err;
		}
		sc_debug(card->ctx, "USING PUB KEY FROM FILE %s",keyfilename);

		bp = BIO_new(BIO_s_file());
		if (bp == NULL) {
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		if (BIO_read_filename(bp, keyfilename) <= 0) {
			BIO_free(bp);
			r = SC_ERROR_FILE_NOT_FOUND;
			goto err;
		}
		rsa = PEM_read_bio_RSAPublicKey(bp, &rsa, NULL, NULL);
		BIO_free(bp);
		if (!rsa) {
			sc_debug(card->ctx,"Unable to load the public key");
			r =  SC_ERROR_DATA_OBJECT_NOT_FOUND; 
			goto err;
        	}


		derlen = i2d_RSAPublicKey(rsa, NULL); 
		if (derlen <= 0) { 
			r =  SC_ERROR_DATA_OBJECT_NOT_FOUND;
			goto err;
		}
		taglen = put_tag_and_len(0x99, derlen, NULL);
		*buf_len = put_tag_and_len(0x53, taglen, NULL);

		*buf = (u8*) malloc(*buf_len);
		if (*buf  == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		q = *buf;

		put_tag_and_len(0x53, taglen, &q);
		put_tag_and_len(0x99, derlen, &q);

		i2d_RSAPublicKey(rsa, &q);
      
		RSA_free(rsa);

		r = *buf_len;

		/* end of read PIV_OBJ_9A06 from file */
	} else {

		if (*buf_len == 1 && *buf == NULL) { /* we need to get the length */
			u8 rbufinitbuf[8]; /* tag of 53 with 82 xx xx  will fit in 4 */
			u8 *rbuf;
			size_t rbuflen;
			size_t bodylen;
			unsigned int cla_out, tag_out;
			const u8 *body;

			sc_debug(card->ctx,"get len of #%d", enumtag);
			rbuf = rbufinitbuf;
			rbuflen = sizeof(rbufinitbuf);
			r = piv_general_io(card, 0xCB, 0x3F, 0xFF, tagbuf,  p - tagbuf,
					&rbuf, &rbuflen);
			if (r > 0) {
				body = rbuf;
				if (sc_asn1_read_tag(&body, 0xffff, &cla_out, &tag_out, &bodylen) !=  SC_SUCCESS) {
					sc_debug(card->ctx, "***** received buffer tag MISSING ");
					r = SC_ERROR_FILE_NOT_FOUND;
					goto err;
				}
			    *buf_len = r;
			} else if ( r == 0) { 
				r = SC_ERROR_FILE_NOT_FOUND;
				goto err;
			} else { 
				goto err;
			}
		}
sc_debug(card->ctx,"get buffer for #%d len %d", enumtag, *buf_len);
		if (*buf == NULL && *buf_len > 0) {
			*buf = (u8*)malloc(*buf_len);
			if (*buf == NULL ) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto err;
			}
		}

		r = piv_general_io(card, 0xCB, 0x3F, 0xFF, tagbuf,  p - tagbuf, 
			buf, buf_len);
	}

err:

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int piv_get_cached_data(sc_card_t * card, int enumtag,
			u8 **buf, size_t *buf_len)
{

	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	u8 *rbuf = NULL;
	size_t rbuflen;
	
	SC_FUNC_CALLED(card->ctx,1);
	sc_debug(card->ctx, "#%d", enumtag);

	assert(enumtag >= 0 && enumtag < PIV_OBJ_LAST_ENUM);

	/* see if we have it cached */
	if (priv->obj_cache[enumtag].flags & PIV_OBJ_CACHE_VALID) {

		sc_debug(card->ctx,"found #%d %p:%d %p:%d",
				enumtag,
				priv->obj_cache[enumtag].obj_data,
				priv->obj_cache[enumtag].obj_len,
				priv->obj_cache[enumtag].internal_obj_data,
				priv->obj_cache[enumtag].internal_obj_len);
				
		
		if (priv->obj_cache[enumtag].obj_len == 0) {
			r = SC_ERROR_FILE_NOT_FOUND;
			sc_debug(card->ctx,"#%d found but len=0",
					enumtag);
			goto err;
		}
		*buf = priv->obj_cache[enumtag].obj_data;
		*buf_len = priv->obj_cache[enumtag].obj_len;
		r = *buf_len;
		goto ok;
	}

	/* not cached get it, piv_get_data will allocate a buf */ 
sc_debug(card->ctx,"get #%d",  enumtag);
	rbuflen = 1; 
	r = piv_get_data(card, enumtag, &rbuf, &rbuflen);
	if (r > 0) {
		priv->obj_cache[enumtag].flags = PIV_OBJ_CACHE_VALID;
		priv->obj_cache[enumtag].obj_len = r;
		priv->obj_cache[enumtag].obj_data = rbuf;
		*buf = rbuf;
		*buf_len = r;

		sc_debug(card->ctx,"added #%d  %p:%d %p:%d",
				enumtag,
				priv->obj_cache[enumtag].obj_data,
				priv->obj_cache[enumtag].obj_len,
				priv->obj_cache[enumtag].internal_obj_data,
				priv->obj_cache[enumtag].internal_obj_len);

	} else if (r == 0 || r == SC_ERROR_FILE_NOT_FOUND) {
		r = SC_ERROR_FILE_NOT_FOUND;
		priv->obj_cache[enumtag].flags = PIV_OBJ_CACHE_VALID; 
		priv->obj_cache[enumtag].obj_len = 0;
	} else if ( r < 0) {
		goto err;
	}
ok:

err:

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int piv_cache_internal_data(sc_card_t *card, int enumtag)
{
	piv_private_data_t * priv = PIV_DATA(card);
	u8* tag;
	u8* body;
	size_t taglen;
	size_t bodylen;
	int compressed = 0;

	/* if already cached */
	if (priv->obj_cache[enumtag].internal_obj_data && priv->obj_cache[enumtag].internal_obj_len) {
		sc_debug(card->ctx,"#%d found internal %p:%d", enumtag, 
				priv->obj_cache[enumtag].internal_obj_data, 
				priv->obj_cache[enumtag].internal_obj_len);
		SC_FUNC_RETURN(card->ctx, 1, 0);
	}	

	body = (u8 *) sc_asn1_find_tag(card->ctx, 
			priv->obj_cache[enumtag].obj_data, 
			priv->obj_cache[enumtag].obj_len,
			0x53, &bodylen);

	if (body == NULL) 
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OBJECT_NOT_VALID);
	
	/* get the certificate out */
	 if (piv_objects[enumtag].flags & PIV_OBJECT_TYPE_CERT) { 
	
		tag = (u8 *) sc_asn1_find_tag(card->ctx, body, bodylen, 0x71, &taglen);
		/* 800-72-1 not clear if this is 80 or 01 Sent comment to NIST for 800-72-2 */
		if (tag && (((*tag) & 0x80) || ((*tag) & 0x01))) {
			compressed = 1;
		}
		tag = (u8 *) sc_asn1_find_tag(card->ctx, body, bodylen, 0x70, &taglen);
		if (tag == NULL) 
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OBJECT_NOT_VALID);
		
		if (taglen == 0)
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_FILE_NOT_FOUND);
	
			if(compressed) {
#ifdef ENABLE_ZLIB
			size_t len;
			u8* newBuf = NULL;
			if(SC_SUCCESS != sc_decompress_alloc(&newBuf, &len, tag, taglen, COMPRESSION_AUTO)) {
				SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OBJECT_NOT_VALID);
			}      
			priv->obj_cache[enumtag].internal_obj_data = newBuf;
			priv->obj_cache[enumtag].internal_obj_len = len;
#else
			sc_error(card->ctx,"PIV compression not supported, no zlib");
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NOT_SUPPORTED);
#endif
		} else {
			if (!(priv->obj_cache[enumtag].internal_obj_data = (u8*)malloc(taglen)))
				SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OUT_OF_MEMORY);

			memcpy(priv->obj_cache[enumtag].internal_obj_data, tag, taglen);
			priv->obj_cache[enumtag].internal_obj_len = taglen;
		}

	/* convert pub key to internal */
	} else if (piv_objects[enumtag].flags & PIV_OBJECT_TYPE_PUBKEY) {

		tag = (u8 *) sc_asn1_find_tag(card->ctx, body, bodylen, *body, &taglen);
		if (tag == NULL)
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OBJECT_NOT_VALID);

		if (taglen == 0)
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_FILE_NOT_FOUND);

		if (!(priv->obj_cache[enumtag].internal_obj_data = (u8*)malloc(taglen)))
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OUT_OF_MEMORY);

		memcpy(priv->obj_cache[enumtag].internal_obj_data, tag, taglen);
		priv->obj_cache[enumtag].internal_obj_len = taglen;
	} else {
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INTERNAL);
	}
				
	sc_debug(card->ctx,"added #%d internal %p:%d", enumtag, 
		priv->obj_cache[enumtag].internal_obj_data,
		priv->obj_cache[enumtag].internal_obj_len);
	
	SC_FUNC_RETURN(card->ctx, 1, 0);
}


/* 
 * Callers of this may be expecting a certificate,
 * select file will have saved the object type for us 
 * as well as set that we want the cert from the object. 
 */
static int piv_read_binary(sc_card_t *card, unsigned int idx,
		unsigned char *buf, size_t count, unsigned long flags)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int enumtag;
	int r;
	u8 *rbuf = NULL;
	size_t rbuflen = 0;
	u8 *body;
	size_t bodylen;

	SC_FUNC_CALLED(card->ctx,1);
	if (priv->selected_obj < 0) 
		 SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INTERNAL);
	enumtag = piv_objects[priv->selected_obj].enumtag;

	if (priv->rb_state == 1) {
		r = 0;
	}

	if (priv->rb_state == -1) {
		r = piv_get_cached_data(card, enumtag, &rbuf, &rbuflen);
	
		if (r >=0) {
			/* an object wih no data will be considered not found */
			if (!rbuf || rbuf[0] == 0x00 || (rbuf[0] == 0x53 && rbuf[1] == 0x00)) {
				r = SC_ERROR_FILE_NOT_FOUND;
				goto err;
			}
			sc_debug(card->ctx, "DEE rbuf=%p,rbuflen=%d,",rbuf, rbuflen);
			body = (u8 *) sc_asn1_find_tag(card->ctx, rbuf, rbuflen, 0x53, &bodylen);
			if (body == NULL) {
				/* if missing, assume its the body */
				/* DEE bug in the beta card */
				sc_debug(card->ctx," ***** tag 0x53 MISSING \n");
				r = SC_ERROR_INVALID_DATA;
				goto err;
			}
			if (bodylen > body - rbuf + rbuflen) {
				sc_debug(card->ctx," ***** tag length > then data: %d>%d+%d",
					bodylen , body - rbuf, rbuflen);
				r = SC_ERROR_INVALID_DATA;
				goto err;
			}
			/* if chached obj has internal interesting data (cert or pub key) */
			if (priv->return_only_cert || piv_objects[enumtag].flags & PIV_OBJECT_TYPE_PUBKEY) {
				r = piv_cache_internal_data(card, enumtag);
				if (r < 0) 
					goto err;
			}
			
		}
		priv->rb_state = 0;
	}

	if (priv->return_only_cert || piv_objects[enumtag].flags & PIV_OBJECT_TYPE_PUBKEY) {
		rbuf = priv->obj_cache[enumtag].internal_obj_data;
		rbuflen = priv->obj_cache[enumtag].internal_obj_len;
	} else {
		rbuf = priv->obj_cache[enumtag].obj_data;
		rbuflen = priv->obj_cache[enumtag].obj_len;
	}
	/* rbuf rbuflen has pointer and length to cached data */

	if ( rbuflen < idx + count)
		count = rbuflen - idx;	
		if (count <= 0) { 
			r = 0;
			priv->rb_state = 1;
		} else { 
			memcpy(buf, rbuf + idx, count);
			r = count;
		}
err:
		SC_FUNC_RETURN(card->ctx, 1, r);
}

  
/*
 * the tag is the PIV_OBJ_*   
 * The buf should have the 0x53 tag+len+tags and data 
 */

static int piv_put_data(sc_card_t *card, int tag, 
		const u8 *buf, size_t buf_len) 
{
	int r;
	u8 * sbuf;
	size_t sbuflen;
	u8 * p;
	size_t tag_len;

	SC_FUNC_CALLED(card->ctx,1);

	tag_len = piv_objects[tag].tag_len;
	sbuflen = put_tag_and_len(0x5c, tag_len, NULL) + buf_len;
	if (!(sbuf = (u8 *) malloc(sbuflen))) 
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OUT_OF_MEMORY);

	p = sbuf;
	put_tag_and_len(0x5c, tag_len, &p);
	memcpy(p, piv_objects[tag].tag_value, tag_len);
	p += tag_len;
	
	memcpy(p, buf, buf_len);
	p += buf_len;

	r = piv_general_io(card, 0xDB, 0x3F, 0xFF, 
			sbuf, p - sbuf, NULL, NULL);

	/* TODO add to cache */
	if (sbuf)
		free(sbuf);
	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int piv_write_certificate(sc_card_t *card,
		unsigned idx, const u8* buf, size_t count,
		unsigned long flags) {
	piv_private_data_t * priv = PIV_DATA(card);
	int enumtag;
	int r = SC_SUCCESS;
	u8 *sbuf = NULL;
	u8 *p;
	size_t sbuflen;
	size_t taglen;

	sc_debug(card->ctx,"DEE cert len=%d",count);
	taglen = put_tag_and_len(0x70, count, NULL) 
		+ put_tag_and_len(0x71, 1, NULL)
		+ put_tag_and_len(0xFE, 0, NULL);

	sbuflen =  put_tag_and_len(0x53, taglen, NULL);

	sbuf = (u8*) malloc(sbuflen);
	if (sbuf == NULL) 
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OUT_OF_MEMORY);
	p = sbuf;
	put_tag_and_len(0x53, taglen, &p);

	put_tag_and_len(0x70, count, &p);
	memcpy(p, buf, count);
	p += count;
	put_tag_and_len(0x71, 1, &p);
	*p++ = (flags && 1)? 0x80:0x00; /* certinfo, i.e. gziped? */
	put_tag_and_len(0xFE,0,&p); /* LRC tag */

	sc_debug(card->ctx,"DEE buf %p len %d %d", sbuf, p -sbuf, sbuflen);

	enumtag = piv_objects[priv->selected_obj].enumtag;
	r = piv_put_data(card, enumtag, sbuf, sbuflen);
	if (sbuf)
		free(sbuf);

	SC_FUNC_RETURN(card->ctx, 1, r);
}
/* 
 * We need to add the 0x53 tag and other specific tags, 
 * and call the piv_put_data 
 * Note: the select file will have saved the object type for us 
 * Write is only used by piv-tool, so we will use flags==1
 * to indicate we are writing a compressed cert. 
 */

static int piv_write_binary(sc_card_t *card, unsigned int idx,
		const u8 *buf, size_t count, unsigned long flags)
{
	piv_private_data_t * priv = PIV_DATA(card);
	SC_FUNC_CALLED(card->ctx,1);

	if (priv->selected_obj < 0)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INTERNAL);
	if (idx != 0)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NO_CARD_SUPPORT);
	
	if (piv_objects[priv->selected_obj].flags & PIV_OBJECT_TYPE_CERT) {
			SC_FUNC_RETURN(card->ctx, 1, piv_write_certificate(card, idx, buf, count, flags));
	} else {
		sc_debug(card->ctx, "Don't know how to write object %s\n",
			piv_objects[priv->selected_obj].name);
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NOT_SUPPORTED);
	}
}

/*
 * Card initialization is not standard.               
 * Some cards use mutual or external authentication using s 3des key. We 
 * will read in the key from a file. 
 * This is only needed during initialization/personalization of the card 
 */

static int piv_get_3des_key(sc_card_t *card, u8 *key)
{

	int r;
	int f = -1; 
	char keybuf[24*3];  /* 3des key as three sets of xx:xx:xx:xx:xx:xx:xx:xx  
		                   * with a : between which is 71 bytes */
	char * keyfilename = NULL;
	size_t outlen;

	SC_FUNC_CALLED(card->ctx,1);

	keyfilename = (char *)getenv("PIV_EXT_AUTH_KEY");

	if (keyfilename == NULL) {
		sc_debug(card->ctx,
			"Unable to get PIV_EXT_AUTH_KEY=filename for general_external_authenticate\n");
		r = SC_ERROR_FILE_NOT_FOUND;
		goto err;
	}
	if ((f = open(keyfilename, O_RDONLY)) < 0) {
		sc_debug(card->ctx," Unable to load 3des key for general_external_authenticate\n");
		r = SC_ERROR_FILE_NOT_FOUND;
		goto err;
	}
	if (read(f, keybuf, 71) != 71) {
		sc_debug(card->ctx," Unable to read 3des key for general_external_authenticate\n");
		r = SC_ERROR_WRONG_LENGTH;  
		goto err;
	}
	keybuf[23] = '\0';
	keybuf[47] = '\0';
	keybuf[71] = '\0';
	outlen = 8;
	r = sc_hex_to_bin(keybuf, key, &outlen);
	if (r) goto err;
	outlen = 8;
	r = sc_hex_to_bin(keybuf+24, key+8, &outlen);
	if (r) goto err;
	outlen = 8;
	r = sc_hex_to_bin(keybuf+48, key+16, &outlen);
	if (r) goto err;
	
err:
	if (f >=0)
		close(f);
	
	SC_FUNC_RETURN(card->ctx, 1, r);
}

/*
 * will only deal with 3des for now
 * assumptions include:
 *  size of encrypted data is same as unencrypted
 *  challenges, nonces etc  from card are less then 114 (keeps tags simple)
 */

static int piv_general_mutual_authenticate(sc_card_t *card, 
	unsigned int key_ref, unsigned int alg_id)
{
	int r;
	int N;
	int locked = 0, outl, outl2;
	u8  *rbuf = NULL;
	size_t rbuflen;
	u8 nonce[8] = {0xDE, 0xE0, 0xDE, 0xE1, 0xDE, 0xE2, 0xDE, 0xE3};
	u8 sbuf[255], key[24];
	u8 *p, *q;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;

	SC_FUNC_CALLED(card->ctx,1);

	EVP_CIPHER_CTX_init(&ctx);

	switch (alg_id) {
		case 1: cipher=EVP_des_ede3_ecb(); break;
		case 2: cipher=EVP_des_ede3_cbc(); break;
		case 3: cipher=EVP_des_ede3_ecb(); break;
		case 4: cipher=EVP_des_ede3_cbc(); break;
		default: cipher=EVP_des_ede3_ecb(); break;
	}

	r = piv_get_3des_key(card, key);
	if (r != SC_SUCCESS)
		goto err;

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		goto err;
	locked = 1;

	p = sbuf;
	q = rbuf;
	*p++ = 0x7C;
	*p++ = 0x02;
	*p++ = 0x80;
	*p++ = 0x00;

	/* get the encrypted nonce */

	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, &rbuf, &rbuflen); 

 	if (r < 0) goto err;
	q = rbuf;
	if ( (*q++ != 0x7C)
		|| (*q++ != rbuflen - 2)
		|| (*q++ != 0x80)
		|| (*q++ != rbuflen - 4)) {
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}
	N = *(rbuf + 3); /* assuming N + sizeof(nonce) + 6 < 128 */

	/* prepare the response */ 
	p = sbuf;
	*p++ = 0x7c;
	*p++ = N + sizeof(nonce)+ 4;
	*p++ = 0x80;
	*p++ = (u8)N; 
	
	/* decrypt the data from the card */
	if (!EVP_DecryptInit(&ctx, cipher, key, NULL)) {
		/* may fail if des parity of key is wrong. depends on OpenSSL options */
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	EVP_CIPHER_CTX_set_padding(&ctx,0);
	if (!EVP_DecryptUpdate(&ctx, p, &outl, q, N)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	if(!EVP_DecryptFinal(&ctx, p+outl, &outl2)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (outl+outl2 != N) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	
	p += N;

	*p++ = 0x81;
	*p++ = sizeof(nonce);
	memcpy(p, &nonce, sizeof(nonce)); /* we use a fixed nonce for now */
	p += sizeof(nonce);

	free(rbuf);
	rbuf = NULL;

	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, &rbuf, &rbuflen); 
 	if (r < 0) goto err;
	q = rbuf;
	if ( (*q++ != 0x7C)
		|| (*q++ != rbuflen - 2)
		|| ((*q++ | 0x02) != 0x82)    /* SP800-73 not clear if  80 or 82 */
		|| (*q++ != rbuflen - 4)) {
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}
	N = *(rbuf + 3); 
	
	p = sbuf;

	EVP_CIPHER_CTX_cleanup(&ctx);
	EVP_CIPHER_CTX_init(&ctx);

	if (!EVP_DecryptInit(&ctx, cipher, key, NULL)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	EVP_CIPHER_CTX_set_padding(&ctx,0);
	if (!EVP_DecryptUpdate(&ctx, p, &outl, q, N)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	if(!EVP_DecryptFinal(&ctx, p+outl, &outl2)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	
	if (outl+outl2 != sizeof(nonce) || memcmp(nonce, p, sizeof(nonce)) != 0) {
		sc_debug(card->ctx, "mutual authentication failed, card returned wrong value");
		r = SC_ERROR_DECRYPT_FAILED;
		goto err;
	}
	r = SC_SUCCESS;

err:
	EVP_CIPHER_CTX_cleanup(&ctx);
	if (locked) 
		sc_unlock(card);
	if (rbuf)
		free(rbuf);

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int piv_general_external_authenticate(sc_card_t *card, 
		unsigned int key_ref, unsigned int alg_id)
{
	/* unused: piv_private_data_t * priv = PIV_DATA(card); */
	int r, outl, outl2;
	int N;
	int locked = 0;
	u8  *rbuf = NULL;
	size_t rbuflen;
	u8 sbuf[255], key[24];
	u8 *p, *q;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;
	
	SC_FUNC_CALLED(card->ctx,1);

	EVP_CIPHER_CTX_init(&ctx);

	switch (alg_id) {
		case 1: cipher=EVP_des_ede3_ecb(); break;
		case 2: cipher=EVP_des_ede3_cbc(); break;
		case 3: cipher=EVP_des_ede3_ecb(); break;
		case 4: cipher=EVP_des_ede3_cbc(); break;
		default: cipher=EVP_des_ede3_ecb(); break;
	}
  
	r = piv_get_3des_key(card, key);
	if (r != SC_SUCCESS)
		goto err;

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		goto err;
	locked = 1;

	p = sbuf;
	q = rbuf;
	*p++ = 0x7C;
	*p++ = 0x02;
	*p++ = 0x81;
	*p++ = 0x00;

	/* get a challenge */

	r = piv_general_io(card, 0x87, 0x00, 0x00, sbuf, p - sbuf, &rbuf, &rbuflen); 

 	if (r < 0) goto err;
	q = rbuf;
	if ( (*q++ != 0x7C)
		|| (*q++ != rbuflen - 2)
		|| (*q++ != 0x81)
		|| (*q++ != rbuflen - 4)) {
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}

	/* assuming challenge and response are same size  i.e. des3 */
	p = sbuf;
	*p++ = 0x7c;
	*p++ = *(rbuf + 1);
	*p++ = 0x82;
	*p++ = *(rbuf + 3);
	N = *(rbuf + 3); /* assuming 2 * N + 6 < 128 */

	if (!EVP_EncryptInit(&ctx, cipher, key, NULL)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	EVP_CIPHER_CTX_set_padding(&ctx,0);
	if (!EVP_EncryptUpdate(&ctx, p, &outl, q, N)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}	
	if(!EVP_EncryptFinal(&ctx, p+outl, &outl2)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	if (outl+outl2 != N) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	p += N;
	
	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, NULL, NULL);

err:
	if (locked)
		sc_unlock(card);
	EVP_CIPHER_CTX_cleanup(&ctx);
	sc_mem_clear(key, sizeof(key));
	if (rbuf)
		free(rbuf);

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int piv_get_serial_nr_from_CHUI(sc_card_t* card, sc_serial_number_t* serial)
{
	int r;
	u8 *rbuf = NULL;
	u8 *body, *fascn;
	size_t rbuflen = 0, bodylen, fascnlen;
	u8 temp[2000];
	size_t templen = sizeof(temp);

	SC_FUNC_CALLED(card->ctx, 1);

	/* ensure we've got the PIV selected, and nothing else is in process */
	/* This fixes several problems due to previous incomplete APDUs during card detection */
	/* Note: We need the temp because (some?) Oberthur cards don't like selecting an applet without response data */
	piv_select_aid(card, piv_aids[0].value, piv_aids[0].len_short, temp, &templen);

	r = piv_get_cached_data(card, PIV_OBJ_CHUI, &rbuf, &rbuflen);
	SC_TEST_RET(card->ctx, r, "Failure retrieving CHUI");

	r = SC_ERROR_INTERNAL;
	if (rbuflen != 0) {
		body = (u8 *)sc_asn1_find_tag(card->ctx, rbuf, rbuflen, 0x53, &bodylen); /* Pass the outer wrapper asn1 */
		if (body != NULL && bodylen != 0) {
			fascn = (u8 *)sc_asn1_find_tag(card->ctx, body, bodylen, 0x30, &fascnlen); /* Find the FASC-N data */
			if (fascn != NULL && fascnlen != 0) {
				serial->len = fascnlen < SC_MAX_SERIALNR ? fascnlen : SC_MAX_SERIALNR;
				memcpy (serial->value, fascn, serial->len);
				r = SC_SUCCESS;
			}
		}
	}
      
//	if (rbuf != NULL)
//		free (rbuf);
	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int piv_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	u8 * opts; /*  A or M, key_ref, alg_id */
 
	opts = (u8 *)ptr;
	
	switch(cmd) {
		case SC_CARDCTL_LIFECYCLE_SET:
			switch (*opts) {
				case 'A':
					return piv_general_external_authenticate(card, 
						*(opts+1), *(opts+2));
					break;
				case'M':
					return piv_general_mutual_authenticate(card, 
						*(opts+1), *(opts+2));
					break;
			}
			break;
		case SC_CARDCTL_CRYPTOFLEX_GENERATE_KEY:
			return piv_generate_key(card, 
				(struct sc_cardctl_cryptoflex_genkey_info *) ptr);
			break;
		case SC_CARDCTL_GET_SERIALNR:
			return piv_get_serial_nr_from_CHUI(card, (sc_serial_number_t *) ptr);
			break;
	}

	return SC_ERROR_NOT_SUPPORTED;
}

static int piv_get_challenge(sc_card_t *card, u8 *rnd, size_t len)
{
	u8 sbuf[16];
	u8 *rbuf = NULL;
	size_t rbuflen = 0;
	u8 *p, *q;
	int r;

	SC_FUNC_CALLED(card->ctx,1);
	
	sc_debug(card->ctx,"challenge len=%d",len);

	sc_lock(card); 

	p = sbuf;
	*p++ = 0x7c;
	*p++ = 0x02;
	*p++ = 0x81;
	*p++ = 0x00;

	/* assuming 8 byte response ? */ 
	/* should take what the card returns */
	while (len > 0) {
		size_t n = len > 8 ? 8 : len;

		r = piv_general_io(card, 0x87, 0x00, 0x00, sbuf, p - sbuf, 
				&rbuf, &rbuflen); 
 		if (r < 0) { 
			sc_unlock(card);
			SC_FUNC_RETURN(card->ctx, 1, r);
		}
		q = rbuf;
		if ( (*q++ != 0x7C)
			|| (*q++ != rbuflen - 2)
			|| (*q++ != 0x81)
			|| (*q++ != rbuflen - 4)) {
			r =  SC_ERROR_INVALID_DATA;
			sc_unlock(card);
			SC_FUNC_RETURN(card->ctx, 1, r);
		}
		memcpy(rnd, q, n);
		len -= n;
		rnd += n;
		free(rbuf);
		rbuf = NULL;
	}

	sc_unlock(card); 

	SC_FUNC_RETURN(card->ctx, 1, 0);

}

static int piv_set_security_env(sc_card_t *card,
                    const sc_security_env_t *env,
                    int se_num)
{
	piv_private_data_t * priv = PIV_DATA(card);
	
	SC_FUNC_CALLED(card->ctx,1);

	sc_debug(card->ctx,"flags=%08x op=%d alg=%d algf=%08x algr=%08x kr0=%02x, krfl=%d\n",
			env->flags, env->operation, env->algorithm, env->algorithm_flags, 
			env->algorithm_ref, env->key_ref[0], env->key_ref_len);

	if (env->algorithm == SC_ALGORITHM_RSA) 
		priv->alg_id = 0x06; /* Say it is RSA, set 5, 6, 7 later */
	else
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NO_CARD_SUPPORT);
	priv->key_ref = env->key_ref[0];

	SC_FUNC_RETURN(card->ctx, 2, 0);
}


static int piv_restore_security_env(sc_card_t *card, int se_num)
{
	SC_FUNC_CALLED(card->ctx,1);

	SC_FUNC_RETURN(card->ctx, 1, 0);
}


static int piv_validate_general_authentication(sc_card_t *card, 
					const u8 * data, size_t datalen,
					u8 * out, size_t outlen)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	u8 *p;
	u8 *tag;
	size_t taglen;
	u8 *body;
	size_t bodylen;
	unsigned int real_alg_id;

	u8 sbuf[4096]; /* needs work. for 3072 keys, needs 384+10 or so */
	u8 *rbuf = NULL;
	size_t rbuflen;
	
	SC_FUNC_CALLED(card->ctx,1);

	/* should assume large send data */
	p = sbuf;
	put_tag_and_len(0x7c, (2 + put_tag_and_len(0, datalen, NULL)) , &p);
	put_tag_and_len(0x82, 0, &p);
	put_tag_and_len(0x81, datalen, &p);

	memcpy(p, data, datalen);
	p += datalen;

	/* 
	 * alg_id=06 is a place holder for all RSA keys. 
 	 * Derive the real alg_id based on the size of the
	 * the data, as we are always using raw mode. 
	 * Non RSA keys needs some work in thia area. 
	 */

	real_alg_id = priv->alg_id;
	if (priv->alg_id == 0x06) {
		switch  (datalen) {
			case 128: real_alg_id = 0x06; break;
			case 256: real_alg_id = 0x07; break;
			case 384: real_alg_id = 0x05; break;
			default:
				SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NO_CARD_SUPPORT);
		}
	} 

	r = piv_general_io(card, 0x87, real_alg_id, priv->key_ref, 
			sbuf, p - sbuf, &rbuf, &rbuflen);  

	if ( r >= 0) {
	 	body = (u8 *) sc_asn1_find_tag(card->ctx, rbuf, rbuflen, 0x7c, &bodylen);
			
		if (body) {
			tag = (u8 *) sc_asn1_find_tag(card->ctx, body,  bodylen, 0x82, &taglen);
			if (tag) {
				memcpy(out, tag, taglen);
				r = taglen;
			}
		} else
			r = SC_ERROR_INVALID_DATA;
	}      

	if (rbuf)
		free(rbuf);

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int piv_compute_signature(sc_card_t *card, 
					const u8 * data, size_t datalen,
					u8 * out, size_t outlen)
{
	SC_FUNC_CALLED(card->ctx,4);
	SC_FUNC_RETURN(card->ctx, 4, piv_validate_general_authentication(card, data, datalen, out, outlen));
}

static int piv_decipher(sc_card_t *card,
					 const u8 * data, size_t datalen,
					 u8 * out, size_t outlen)
{
	SC_FUNC_CALLED(card->ctx,4);

	SC_FUNC_RETURN(card->ctx, 4, piv_validate_general_authentication(card, data, datalen, out, outlen));
}


static int piv_find_obj_by_containerid(sc_card_t *card, const u8 * str)
{
	int i;

	SC_FUNC_CALLED(card->ctx,4);
	sc_debug(card->ctx, "str=0x%02X%02X\n", str[0], str[1]);

	for (i = 0; piv_objects[i].enumtag < PIV_OBJ_LAST_ENUM; i++) {
		if ( str[0] == piv_objects[i].containerid[0] 
			&& str[1] == piv_objects[i].containerid[1])
			SC_FUNC_RETURN(card->ctx, 4, i);
	}
	SC_FUNC_RETURN(card->ctx, 4, -1);
}


/*
 * the PIV-II does not always support files, but we will simulate
 * files and reading/writing using get/put_data
 * The path is the containerID number 
 * We can use this to determine the type of data requested, like a cert
 * or pub key. 
 * We only support write from the piv_tool with file_out==NULL 
 * All other requests should be to read.  
 * Only if file_out != null, will we read to get length. 
 */
static int piv_select_file(sc_card_t *card, const sc_path_t *in_path,
	sc_file_t **file_out)
{
 	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	int i;
	const u8 *path;
	int pathlen;
	sc_file_t *file = NULL;
	u8 * rbuf = NULL;
	size_t rbuflen = 0;
	
	SC_FUNC_CALLED(card->ctx,1);

	path = in_path->value;
	pathlen = in_path->len;
	
	/* only support single EF in current application */

	if (pathlen > 2 && memcmp(path, "\x3F\x00", 2) == 0) {
		path += 2;
		pathlen -= 2;
	}
	 
	i = piv_find_obj_by_containerid(card, path);

	if (i < 0)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_FILE_NOT_FOUND); 
	
	/*
	 * pkcs15 will use a 2 byte path or a 4 byte path 
	 * with cece added to path to request only the cert from the cert obj 
	 * PIV "Container ID" is used as the path, and are two bytes long
	 */
	priv->return_only_cert = (pathlen == 4 && path[2] == 0xce && path[3] == 0xce);
	    
	priv->selected_obj = i;
	priv->rb_state = -1;
	
	/* make it look like the file was found. */
	/* We don't want to read it now  unless we need the length */ 
	
	if (file_out) {
		/* we need to read it now, to get length into cache */
		sc_ctx_suppress_errors_on(card->ctx);
		r = piv_get_cached_data(card, i, &rbuf, &rbuflen); 
		sc_ctx_suppress_errors_off(card->ctx);
	
		if (r < 0)
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_FILE_NOT_FOUND);

		/* get the cert or the pub key out and into the cache too */
		if (priv->return_only_cert || piv_objects[i].flags & PIV_OBJECT_TYPE_PUBKEY) { 
			r = piv_cache_internal_data(card, i);
			if (r < 0)
				SC_FUNC_RETURN(card->ctx, 1, r);
		}
			
		file = sc_file_new();
		if (file == NULL)
			SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);

		file->path = *in_path;
		/* this could be like the FCI */
		file->type =  SC_FILE_TYPE_DF;
		file->shareable = 0;
		file->ef_structure = 0;
		if (priv->return_only_cert)
			file->size = priv->obj_cache[i].internal_obj_len;
		else 
			file->size = priv->obj_cache[i].obj_len;

		file->id = (piv_objects[i].containerid[0]<<8) + piv_objects[i].containerid[1];

		*file_out = file;
	}

	SC_FUNC_RETURN(card->ctx, 1, 0);

}


static int piv_finish(sc_card_t *card)
{
 	piv_private_data_t * priv = PIV_DATA(card);
	int i; 

	SC_FUNC_CALLED(card->ctx,1);
	if (priv) {
		if (priv->aid_file)
			sc_file_free(priv->aid_file);
		for (i = 0; i < PIV_OBJ_LAST_ENUM - 1; i++) {
sc_debug(card->ctx,"DEE freeing #%d, %p:%d %p:%d", i, 
				priv->obj_cache[i].obj_data, priv->obj_cache[i].obj_len,
				priv->obj_cache[i].internal_obj_data, priv->obj_cache[i].internal_obj_len);
			if (priv->obj_cache[i].obj_data)
				free(priv->obj_cache[i].obj_data);
			if (priv->obj_cache[i].internal_obj_data)
				free(priv->obj_cache[i].internal_obj_data);
		}
		free(priv);
	}
/* TODO temp see piv_init */
	sc_ctx_suppress_errors_off(card->ctx);
	return 0;
}


static int piv_match_card(sc_card_t *card)
{
	int i;
	sc_file_t aidfile;
	SC_FUNC_CALLED(card->ctx,1);
	/* Since we send an APDU, the card's logout function may be called...
	 * however it may be in dirty memory */
	card->ops->logout = NULL;

	/* Detect by selecting applet */
	sc_ctx_suppress_errors_on(card->ctx);
	i = !(piv_find_aid(card, &aidfile));
	sc_ctx_suppress_errors_off(card->ctx);
	return i; /* never match */
}


static int piv_init(sc_card_t *card)
{
	int r;
	unsigned long flags;
	piv_private_data_t *priv;

	SC_FUNC_CALLED(card->ctx,1);
	priv = (piv_private_data_t *) calloc(1, sizeof(piv_private_data_t));

	if (!priv)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OUT_OF_MEMORY);
	priv->aid_file = sc_file_new();
	priv->selected_obj = -1;
	priv->max_recv_size = 256;
	/* priv->max_recv_size = card->max_recv_size; */
	priv->max_send_size = card->max_send_size;
	/* TODO fix read_binary and write_binary (read_binary is fixed) */
	card->max_recv_size = 0xffff; /* must force pkcs15 read_binary in one call */
	card->max_send_size = 0xffff;
	
	sc_debug(card->ctx, "Max send = %d recv = %d\n", 
			card->max_send_size, card->max_recv_size);
	card->drv_data = priv;
	card->cla = 0x00;
	card->name = "PIV-II card";

	r = piv_find_aid(card, priv->aid_file);
	if (r < 0) {
		 sc_error(card->ctx, "Failed to initialize %s\n", card->name);
		SC_FUNC_RETURN(card->ctx, 1, r);
	}
	priv->enumtag = piv_aids[r].enumtag;
	card->type = piv_aids[r].enumtag;

	 flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_ONBOARD_KEY_GEN;
	
	_sc_card_add_rsa_alg(card, 1024, flags, 0); /* manditory */
	_sc_card_add_rsa_alg(card, 2048, flags, 0); /* optional */
	_sc_card_add_rsa_alg(card, 3072, flags, 0); /* optional */
	
	card->caps |= SC_CARD_CAP_RNG;

	if (r > 0)
		r = 0;
sc_ctx_suppress_errors_on(card->ctx); /*TODO temp to suppresss all error */
	SC_FUNC_RETURN(card->ctx, 1, r);
}


static int piv_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, 
                       int *tries_left)
{
	/* Extra validation of (new) PIN during a PIN change request, to
	 * ensure it's not outside the FIPS 201 4.1.6.1 (numeric only) and
	 * FIPS 140-2 (6 character minimum) requirements.
	 */
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	if (data->cmd == SC_PIN_CMD_CHANGE) {
		int i = 0;
		if (data->pin2.len < 6) {
			return SC_ERROR_INVALID_PIN_LENGTH;
		}
		for(i=0; i < data->pin2.len; ++i) {
			if (!isdigit(data->pin2.data[i])) {
				return SC_ERROR_INVALID_DATA;
			}
		}
	}
	return iso_drv->ops->pin_cmd(card, data, tries_left);
}


static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	piv_ops = *iso_drv->ops;
	piv_ops.match_card = piv_match_card;
	piv_ops.init = piv_init;
	piv_ops.finish = piv_finish;
	
	piv_ops.select_file =  piv_select_file; /* must use get/put, could emulate? */
	piv_ops.get_challenge = piv_get_challenge;
	piv_ops.read_binary = piv_read_binary;
	piv_ops.write_binary = piv_write_binary;
	piv_ops.set_security_env = piv_set_security_env;
	piv_ops.restore_security_env = piv_restore_security_env;
	piv_ops.compute_signature = piv_compute_signature;
	piv_ops.decipher =  piv_decipher;
	piv_ops.card_ctl = piv_card_ctl;
	piv_ops.pin_cmd = piv_pin_cmd;

	return &piv_drv;
}


#if 1
struct sc_card_driver * sc_get_piv_driver(void)
{
	return sc_get_driver();
}
#endif

#endif
