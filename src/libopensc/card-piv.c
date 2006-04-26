/*
 * card-piv.c: Support for PIV-II from NIST SP800-73 
 * card-default.c: Support for cards with no driver
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2005, Douglas E. Engert <deengert@anl.gov>
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
#include <string.h>
#include <fcntl.h>
#include <openssl/des.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "asn1.h"
#include "cardctl.h"

struct piv_private_data {
	struct sc_pin_cmd_pin pin_info;
	sc_file_t *aid_file;
	int enumtag;
	int  selected_obj; /* The index into the piv_objects last selected */
	int  eof;
	size_t max_recv_size; /* saved size, need to lie to pkcs15_read_file */
	size_t max_send_size; 
	int key_ref; /* saved from set_security_env and */
	int alg_id;  /* used in decrypy, signature */ 
};

struct piv_aid {
	int enumtag;
	size_t len_short;	/* min lenght without version */
	size_t len_long;	/* With version and other stuff */
	u8 *value;
};
 
/* The Generic entry should be the "A0 00 00 03 08 00 00 01 00 "
 * NIST published  this on 10/6/2005   
 */ 
static struct piv_aid piv_aids[] = {
	{SC_CARD_TYPE_PIV_II_GENERIC, 
		 9, 11, (u8 *) "\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00" },
	{0,  9, 0, NULL }
};

enum {
	PIV_OBJ_CCC = 1,
	PIV_OBJ_CHUI,
	PIV_OBJ_X509_PIV_AUTH,
	PIV_OBJ_CHF1,
	PIV_OBJ_CHF2,
	PIV_OBJ_PI,
	PIV_OBJ_CHFI,
	PIV_OBJ_X509_DS,
	PIV_OBJ_X509_KM,
	PIV_OBJ_X509_CARD_AUTH,
	PIV_OBJ_SEC_OBJ,
	PIV_OBJ_9B03,
	PIV_OBJ_9A06
};

struct piv_object {
	int enumtag;
	const char * name;
	const char * oidstring;
	size_t tag_len;
	u8  tag_value[3];
	u8  containerid[2];	/* will use as relative paths for simulation */
	size_t maxlen;		/* advisory, used with select_file, but we can read larger */
};

static struct piv_object piv_objects[] = { 
	{ PIV_OBJ_CCC, "Card Capability Container", 
			"2.16.840.1.101.3.7.1.219.0", 3, "\x5F\xC1\x07", "\xDB\x00", 266},
	{ PIV_OBJ_CHUI, "Card Holder Unique Identifier", 
			"2.16.840.1.101.3.7.2.48.0", 3, "\x5F\xC1\x02", "\x30\x00", 3377},
	{ PIV_OBJ_X509_PIV_AUTH, "X.509 Certificate for PIV Authentication", 
			"2.16.840.1.101.3.7.2.1.1", 3, "\x5F\xC1\x05", "\x01\x01", 1856+4+400} , 
		/* extra 400 is hack for MultOS card which returns 2200 bytes  */
	{ PIV_OBJ_CHF1, "Card Holder Fingerprint I",
			"2.16.840.1.101.3.7.2.96.16", 3, "\x5F\xC1\x03", "\x60\x01", 7768},
	{ PIV_OBJ_CHF2, "Card Holder Fingerprint II",
			"2.16.840.1.101.3.7.2.96.17", 3, "\x5F\xC1\x04", "\x60\x11", 7768},
	{ PIV_OBJ_PI, "Printed Information", 
			"2.16.840.1.101.3.7.2.48.1", 3, "\x5F\xC1\x09", "\x30\x01", 106},
	{ PIV_OBJ_CHFI, "Card Holder Facial Image",
			"2.16.840.1.101.3.7.2.96.48", 3, "\x5F\xC1\x08", "\x60\x30", 12704},
	{ PIV_OBJ_X509_DS, "X.509 Certificate for Digital Signature",
			"2.16.840.1.101.3.7.2.1.0", 3, "\x5F\xC1\x0A", "\x01\x00", 1856+4},
	{ PIV_OBJ_X509_KM, "X.509 Certificate for Key Management",
			"2.16.840.1.101.3.7.2.1.2", 3, "\x5F\xC1\x0B", "\x01\x02", 1856+4},
	{ PIV_OBJ_X509_CARD_AUTH, "X.509 Certificate for Card Authentication",
			"2.16.840.1.101.3.7.2.5.0", 3, "\x5F\xC1\x01", "\x05\x00", 1856+4}, 
	{ PIV_OBJ_SEC_OBJ, "Security Object", 
			"2.16.840.1.101.3.7.2.144.0", 3, "\x5F\xC1\x06", "\x90\x00", 1000}, 
/* following not standard , to be used by piv-tool only for testing */
	{ PIV_OBJ_9B03, "3DES-ECB ADM", 
			"2.16.840.1.101.3.7.2.9999.3", 2, "\x9B\x03", "\x9B\x03", 24},
	{ PIV_OBJ_9A06, "Pub key from last genkey",
			"2.16.840.1.101.3.7.2.9999.20", 2, "\x9A\x06", "\x9A\x06", 255},
	/* need other RSA types */
	{ 0, "", "", 0, "", "", 0}
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
 * oterwise, store tag and length at **ptr, and increment
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


static int piv_logout(sc_card_t * card)
{
	SC_FUNC_CALLED(card->ctx,1);
	/* 
	 * nothing to do here, as we dont have files on the card.  
	 */ 
	return 0;
}


/*
 * Send a command and receive data. Receive as much as the card indicates 
 * in the first segment. There is always something to send. 
 * Used by  GET DATA, PUT DATA, GENERAL AUTHENTICATE 
 * and GENERATE ASYMMETRIC KEY PAIR.
 * SELECT could too.
 * 
 * For now we will use a large buffer. What we should be doing is using  a 
 * the TLV in the first few bytes to see how large the object is and 
 * allocating a buffer. 
 */

static int piv_general_io(sc_card_t *card, int ins, int p1, int p2, 
	const u8 * sendbuf, size_t sendbuflen, u8 ** recvbuf,
	size_t * recvbuflen)
{
	struct piv_private_data * priv = (struct piv_private_data *) card->drv_data;
	int r;
	sc_apdu_t apdu;
	u8 rbufinitbuf[20000]; /* crude way to do this  see above comments */
	u8 *rbuf;
	size_t rbuflen;
	unsigned int cla_out, tag_out;
	const u8 *body;
	size_t bodylen;

	SC_FUNC_CALLED(card->ctx,1);

	
	sc_debug(card->ctx, "piv_general_io %02x %02x %02x %d : %d %d\n",
		 ins, p1, p2, sendbuflen , priv->max_send_size, priv->max_recv_size);

	rbuf = rbufinitbuf;
	rbuflen = sizeof(rbufinitbuf);

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		return r;
		
	sc_format_apdu(card, &apdu, 
			recvbuf ? SC_APDU_CASE_4_SHORT: SC_APDU_CASE_3_SHORT, 
			ins, p1, p2);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	apdu.lc = sendbuflen;
	apdu.datalen = sendbuflen;
	apdu.data = sendbuf;

	if (recvbuf) {
		apdu.resp = rbuf;
		apdu.le = priv->max_recv_size;
		apdu.resplen = rbuflen;
	} else {
		 apdu.resp =  rbuf;
		 apdu.le = 0;
		 apdu.resplen = 0;
	}

	card->max_recv_size = priv->max_recv_size;

	sc_debug(card->ctx,"calling sc_transmit_apdu flags=%x le=%d, resplen=%d, resp=%p", 
		apdu.flags, apdu.le, apdu.resplen, apdu.resp);

	/* with new adpu.c and chaining, this actually reads the whole object */
	r = sc_transmit_apdu(card, &apdu);
	card->max_recv_size = 0xffff;

	sc_debug(card->ctx,"DEE  r=%d apdu.resplen=%d sw1=%02x sw2=%02x", 
			r, apdu.resplen, apdu.sw1, apdu.sw2);
	if (r < 0) {
		sc_debug(card->ctx,"Transmit failed");
		goto err;
	}
			
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	
	if (r < 0) {
		sc_debug(card->ctx, "Card returned error ");
		goto err;
	}

	/*
	 * See how much we read and if we need to read more 
	 * We should have read a tag, which will tell up how big of 
	 * a buffer we need. We will then read more in to the allocated buffer 
	 */  

	if ( recvbuflen && recvbuf && apdu.resplen > 3) {
		*recvbuflen = 0;
		/* we should have all the tag data, so we have to tell sc_asn1_find_tag 
		 * the buffer is bigger, so it will not produce "ASN1.tag too long!" */

		body = rbuf;
		if (sc_asn1_read_tag(&body, 0xffff, &cla_out, &tag_out, &bodylen) !=  SC_SUCCESS) 		{
			sc_debug(card->ctx, "***** received buffer tag MISSING ");
			body = rbuf;
			/* some readers/cards might return 6c 00 */ 
			if (apdu.sw1 == 0x61  || apdu.sw2 == 0x6c ) 
				bodylen = 12000;
			else
				bodylen = apdu.resplen;
		}
		rbuflen = body - rbuf + bodylen;
		*recvbuf = (u8 *)malloc(rbuflen); 
		sc_debug(card->ctx, "DEE got buffer %p len %d",*recvbuf,  rbuflen);
		if (*recvbuf == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(*recvbuf, rbuf, rbuflen); /* copy tag too */
	} 
	/* If we only read part of the object, we would continue chaining, but the
	 * apdu.c chaining code has already read all the data */
	priv->eof = 1;

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
		r = 0;
	}
	
err:
	if (rbuf)
		free(rbuf);
	SC_FUNC_RETURN(card->ctx, 1, r);
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

	SC_FUNC_CALLED(card->ctx,1);

	/* first  see if the default applcation will return a template
	 * that we know about. 
	 */

	if (card->type == SC_CARD_TYPE_PIV_II_GENERIC) 
		SC_FUNC_RETURN(card->ctx, 1, 0);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
	apdu.lc = piv_aids[0].len_short;
	apdu.data = piv_aids[0].value;
	apdu.datalen = piv_aids[0].len_short;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256; /* could be 21  for fci */

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r >= 0 && apdu.resplen > 2 ) {
		tag = (u8 *) sc_asn1_find_tag(card->ctx, rbuf, apdu.resplen, 0x61, &taglen);
		if (tag != NULL) {
			pix = (u8 *) sc_asn1_find_tag(card->ctx, tag, taglen, 0x4F, &pixlen);
			if (pix != NULL ) { 
				sc_debug(card->ctx,"found PIX");
		 
				/* early cards returned full AID, rather then just the pix */
				for (i = 0; piv_aids[i].len_short != 0; i++) {
					if ((pixlen >= 6 && memcmp(pix, piv_aids[i].value + 5, 6) == 0)
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
static int piv_get_data(sc_card_t * card, unsigned int enumtag, 
			u8 **buf, size_t *buf_len)
{
	struct piv_private_data * priv = (struct piv_private_data *) card->drv_data;
	u8 *p;
	int r = 0;
	u8 tagbuf[8];
	size_t tag_len;
		
	SC_FUNC_CALLED(card->ctx,1);
	sc_debug(card->ctx, "get_data: tag=%d \n", enumtag);

	tag_len = piv_objects[enumtag].tag_len;

	p = tagbuf;
	put_tag_and_len(0x5c, tag_len, &p);
	memcpy(p, piv_objects[enumtag].tag_value, tag_len);
	p += tag_len;


	/*
	 * the PIV card will only recover the public key during a generate
	 * key operation. If the piv-tool was used it would save this
	 * as an OpenSSL EVP_KEY PEM using the -o parameter
	 * we will look to see there as a file and load it
	 * this is ugly, and maybe the pkcs15 cache would work
	 * but we only need it  to get the OpenSSL req with engine to work.
	 */


	if (piv_objects[enumtag].enumtag == PIV_OBJ_9A06)  {
		BIO * bp = NULL;
		RSA * rsa = NULL;
		u8 *q;
		size_t derlen;
		size_t taglen;
		char * keyfilename = NULL;

		keyfilename = getenv("PIV_9A06_KEY");

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
	
		priv->eof = 1;

		/* end of read PIV_OBJ_9A06 from file */
	} else {

		r = piv_general_io(card, 0xCB, 0x3F, 0xFF, tagbuf,  p - tagbuf, 
			buf, buf_len);
	}

err:

	SC_FUNC_RETURN(card->ctx, 1, r);
}
	  
/* 
 * Callers of this are expecting a file without tags,
 * So we need to know what type of file this is, so we can get the
 * correct object out of the taged data returned by get_data
 * Note the select file will have saved the object type for us. 
 */
static int piv_read_binary(sc_card_t *card, unsigned int idx,
		unsigned char *buf, size_t count, unsigned long flags)
{
	struct piv_private_data * priv = (struct piv_private_data *) card->drv_data;
	int r;
	u8 *rbuf = NULL;
	size_t rbuflen = 0;
	u8 *tag;
	size_t taglen;
	u8 *body;
	size_t bodylen;

	SC_FUNC_CALLED(card->ctx,1);
	if (priv->selected_obj < 0) 
		 SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INTERNAL);

	if (priv->eof == 1)
		return 0;

	r = piv_get_data(card, priv->selected_obj, &rbuf, &rbuflen);
	
	if (r >=0) {
		/* if tag is 0, assume card is telling us no object on card */
		if (rbuf[0] == '0') {
			r = SC_ERROR_FILE_NOT_FOUND;
			goto err;
		}
		sc_debug(card->ctx, "DEE rbuf=%p,rbuflen=%d,",rbuf, rbuflen);
		body = (u8 *) sc_asn1_find_tag(card->ctx, rbuf, rbuflen, 0x53, &bodylen);
		if (body == NULL) {
			/* if missing, assume its the body */
			/* DEE bug in the beta card */
			sc_debug(card->ctx," ***** tag 0x53 MISSING \n");
			body =  rbuf;
			bodylen = rbuflen;
#if 0
			r = SC_ERROR_INVALID_DATA;
			goto err;
#endif
		}
		switch (piv_objects[priv->selected_obj].enumtag) {
			case PIV_OBJ_X509_PIV_AUTH:
			case PIV_OBJ_X509_DS:
			case PIV_OBJ_X509_KM:
			case PIV_OBJ_X509_CARD_AUTH:
				/* get the certificate out */
				tag = (u8 *) sc_asn1_find_tag(card->ctx, body,  bodylen, 0x70, &taglen);
				if (tag == NULL) {
					r = SC_ERROR_OBJECT_NOT_VALID;
					break;
				}
				memcpy(buf, tag, taglen); /*DEE should check lengths */
				r = taglen;
				tag = (u8 *) sc_asn1_find_tag(card->ctx, body,  bodylen, 0x71, &taglen);
				if (tag && ((*tag) & 0x80)) {
					sc_debug(card->ctx,0,"Cert is gziped! %0x2.2x\n",*tag);
				}
				break;
			default:
				/* For now get the first tag, and return the data */
				tag = (u8 *) sc_asn1_find_tag(card->ctx, body,  bodylen, *body, &taglen);
				if (tag == NULL) {
					r = SC_ERROR_OBJECT_NOT_VALID;
					break;
				}
				memcpy(buf, tag, taglen); /*DEE should check lengths */
				r = taglen;
				break;
		}
	}
err:
	if (rbuf)
		free(rbuf);
	SC_FUNC_RETURN(card->ctx, 1, r);
}

  
/*
 * the tag is the PIV_OBJ_*   
 * The buf should have the 0x53 tag+len+tags and data 
 */

static int piv_put_data(sc_card_t *card, unsigned int tag, 
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
		return SC_ERROR_OUT_OF_MEMORY;

	p = sbuf;
	put_tag_and_len(0x5c, tag_len, &p);
	memcpy(p, piv_objects[tag].tag_value, tag_len);
	p += tag_len;
	
	memcpy(p, buf, buf_len);
	p += buf_len;

	r = piv_general_io(card, 0xDB, 0x3F, 0xFF, 
			sbuf, p - sbuf, NULL, NULL);

	if (sbuf)
		free(sbuf);
	SC_FUNC_RETURN(card->ctx, 1, r);
}


/* 
 * We need to add the 0x53 tag and other specific tags, 
 * and call the piv_put_data 
 * Note: the select file will have saved the object type for us 
 */

static int piv_write_binary(sc_card_t *card, unsigned int idx,
		const u8 *buf, size_t count, unsigned long flags)
{
	struct piv_private_data * priv = (struct piv_private_data *) card->drv_data;
	int r = 0;
	u8 *sbuf = NULL;
	u8 *p;
	size_t sbuflen;
	size_t taglen;
	
	SC_FUNC_CALLED(card->ctx,1);

	if (priv->selected_obj < 0)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INTERNAL);
	if (idx != 0)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NO_CARD_SUPPORT);
	
	switch (piv_objects[priv->selected_obj].enumtag) {
		case PIV_OBJ_X509_PIV_AUTH:
		case PIV_OBJ_X509_DS:
		case PIV_OBJ_X509_KM:
		case PIV_OBJ_X509_CARD_AUTH:
		sc_debug(card->ctx,"DEE cert len=%d",count);
		
			taglen = put_tag_and_len(0x70, count, NULL) 
				+ put_tag_and_len(0x71, 1, NULL);

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
			*p++ = 0x00; /* certinfo, i.e. not gziped */
			sc_debug(card->ctx,"DEE buf %p len %d %d", sbuf, p -sbuf, sbuflen);
			break;
			
		default:
		sc_debug(card->ctx, "Don't know how to write object %s\n",
			piv_objects[priv->selected_obj].name);
			r = SC_ERROR_NOT_SUPPORTED;
			break;
	}

	if (r == 0) 
		r = piv_put_data(card, priv->selected_obj, sbuf, sbuflen);
	if (sbuf)
		free(sbuf);

	SC_FUNC_RETURN(card->ctx, 1, r);
}

/*
 * Card initialization is not standard.               
 * Some cards use mutual or external authentication using s 3des key. We 
 * will read in the key from a file. 
 * This is only needed during initialization/personalization of the card 
 */

static int piv_get_3des_key(sc_card_t *card, 
		DES_cblock *k1, DES_cblock *k2,  DES_cblock *k3)
{

	int r;
	int f = -1; 
	char keybuf[24*3-1];  /* 3des key as three sets of xx:xx:xx:xx:xx:xx:xx:xx  
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
	outlen = 8;
	r = sc_hex_to_bin(keybuf, *k1, &outlen);
	if (r) goto err;
	outlen = 8;
	r = sc_hex_to_bin(keybuf+24, *k2, &outlen);
	if (r) goto err;
	outlen = 8;
	r = sc_hex_to_bin(keybuf+48, *k3, &outlen);
	if (r) goto err;
	
err:
	if (f >=0)
		close(f);
	
	SC_FUNC_RETURN(card->ctx, 1, r);
}

/*
 * will only deal with 3des for now
 */

static int piv_general_mutual_authenticate(sc_card_t *card, 
	unsigned int key_ref, unsigned int alg_id)
{
	int r;
	size_t N;
	int locked = 0;
	u8  *rbuf = NULL;
	size_t rbuflen;
	u8 nonce[8] = {0xDE, 0xE0, 0xDE, 0xE1, 0xDE, 0xE2, 0xDE, 0xE3};
	u8 sbuf[255];
	u8 *p, *q;
	
	DES_cblock k1, k2, k3;
	DES_key_schedule ks1, ks2, ks3;

	SC_FUNC_CALLED(card->ctx,1);

	r = piv_get_3des_key(card, &k1, &k2, &k3);
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
	N = *(rbuf + 3); /* assuming 2 * N + 6 < 128  and N = 8 */

	/* needs work, as challenge may be other then 8 bytes */
	/* prepare the response */ 
	p = sbuf;
	*p++ = 0x7c;
	*p++ = 2 * N + 4;
	*p++ = 0x80;
	*p++ = (u8)N; 
	
	DES_set_key((DES_cblock *) &k1, &ks1);
	DES_set_key((DES_cblock *) &k2, &ks2);
	DES_set_key((DES_cblock *) &k3, &ks3);
	/* FIXME */
	DES_ecb3_encrypt((const_DES_cblock *)q, (DES_cblock *)p, &ks1, &ks2, &ks3, DES_DECRYPT);
	p += N;

	*p++ = 0x81;
	*p++ = N;
	memcpy(p, &nonce, N); /* we use a fixed nonce for now */
	p += N;

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
	
	DES_set_key((DES_cblock *) &k1, &ks1);
	DES_set_key((DES_cblock *) &k2, &ks2);
	DES_set_key((DES_cblock *) &k3, &ks3);
	
	p = sbuf;
	/* FIXME */
	DES_ecb3_encrypt((const_DES_cblock *)q, (DES_cblock *)p, &ks1, &ks2, &ks3, DES_DECRYPT);
	
	if (memcmp(nonce, p, N) != 0) {
		sc_debug(card->ctx, "mutual authentication failed, card returned wrong value");
		r = SC_ERROR_DECRYPT_FAILED;
		goto err;
	}
	r = 0;

err:
	if (locked) 
		sc_unlock(card);
	if (rbuf)
		free(rbuf);

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int piv_general_external_authenticate(sc_card_t *card, 
		unsigned int key_ref, unsigned int alg_id)
{
	struct piv_private_data * priv = (struct piv_private_data *) card->drv_data;
	int r;
	u8  *rbuf = NULL;
	size_t rbuflen;
	u8 sbuf[255];
	u8 *p, *q;
	
	DES_cblock k1, k2, k3;
	DES_key_schedule ks1, ks2, ks3;

	SC_FUNC_CALLED(card->ctx,1);

	r = piv_get_3des_key(card, &k1, &k2, &k3);
	if (r != SC_SUCCESS)
		goto err;

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		goto err;

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

	/* needs work, as challenge may be other then 8 bytes */
	p = sbuf;
	*p++ = 0x7c;
	*p++ = *(rbuf + 1);
	*p++ = 0x82;
	*p++ = *(rbuf + 3);
	
	DES_set_key((DES_cblock *) &k1, &ks1);
	DES_set_key((DES_cblock *) &k2, &ks2);
	DES_set_key((DES_cblock *) &k3, &ks3);
	
	DES_ecb3_encrypt((const_DES_cblock *)q, (DES_cblock *)p, &ks1, &ks2, &ks3, DES_ENCRYPT);
	p += *(rbuf + 3);
	
	switch (priv-> enumtag) {
		default:
			alg_id = 0x00;
	}
	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, NULL, NULL);

	sc_unlock(card);

err:
	if (rbuf)
		free(rbuf);

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
 		if (r < 0) 
			SC_FUNC_RETURN(card->ctx, 1, r);
		q = rbuf;
		if ( (*q++ != 0x7C)
			|| (*q++ != rbuflen - 2)
			|| (*q++ != 0x81)
			|| (*q++ != rbuflen - 4)) {
			r =  SC_ERROR_INVALID_DATA;
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
	struct piv_private_data * priv = (struct piv_private_data *) card->drv_data;
	
	SC_FUNC_CALLED(card->ctx,1);

	sc_debug(card->ctx,"flags=%08x op=%d alg=%d algf=%08x algr=%08x kr0=%02x, krfl=%d\n",
			env->flags, env->operation, env->algorithm, env->algorithm_flags, 
			env->algorithm_ref, env->key_ref[0], env->key_ref_len);

	if (env->algorithm == 0) 
		priv->alg_id = 0x06; /* 1024 RSA for now only */
	else
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NO_CARD_SUPPORT);
	priv->key_ref = env->key_ref[0];

	return 0;
}


static int piv_restore_security_env(sc_card_t *card, int se_num)
{
	SC_FUNC_CALLED(card->ctx,1);

	return 0;
}


static int piv_validate_general_authentication(sc_card_t *card, 
					const u8 * data, size_t datalen,
					u8 * out, size_t outlen)
{
	struct piv_private_data * priv = (struct piv_private_data *) card->drv_data;
	int r;
	u8 *p;
	u8 *tag;
	size_t taglen;
	u8 *body;
	size_t bodylen;

	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
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

	r = piv_general_io(card, 0x87, priv->alg_id, priv->key_ref, 
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
	return piv_validate_general_authentication(card, data, datalen, out, outlen);
}

static int piv_decipher(sc_card_t *card,
					 const u8 * data, size_t datalen,
					 u8 * out, size_t outlen)
{
	SC_FUNC_CALLED(card->ctx,4);

	return piv_validate_general_authentication(card, data, datalen, out, outlen);
}


static int piv_find_obj_by_containerid(sc_card_t *card, const u8 * str)
{
	int i;

	SC_FUNC_CALLED(card->ctx,4)
	sc_debug(card->ctx, "str=0x%02X%02X\n", str[0], str[1]);

	for (i = 0; piv_objects[i].enumtag; i++) {
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
 */
static int piv_select_file(sc_card_t *card, const sc_path_t *in_path,
	sc_file_t **file_out)
{
 	struct piv_private_data * priv = (struct piv_private_data *) card->drv_data;
	int i;
	const u8 *path;
	int pathlen;
	sc_file_t *file = NULL;
	
	SC_FUNC_CALLED(card->ctx,1)

	path = in_path->value;
	pathlen = in_path->len;
	
	/* only support single EF in current application */

	if (pathlen > 2 && memcmp(path, "\x3F\x00", 2) == 0) {
		path += 2;
		pathlen -= 2;
	}
	if (pathlen != 2)
			return SC_ERROR_INVALID_ARGUMENTS;
	 
	i = piv_find_obj_by_containerid(card, path);

	if (i< 0)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_FILE_NOT_FOUND); 
	priv->selected_obj = i;
	priv->eof = 0;

	/* make it look like the file was found. We don't want to read it now,. */ 

	if (file_out) {
		file = sc_file_new();
		if (file == NULL)
			SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);

		file->path = *in_path;
		/* this could be like the FCI */
		file->type =  SC_FILE_TYPE_DF;
		file->shareable = 0;
		file->ef_structure = 0; 
		file->size = piv_objects[i].maxlen;
		file->id = (piv_objects[i].containerid[0]<<8) + piv_objects[i].containerid[1];

		*file_out = file;
	}

	SC_FUNC_RETURN(card->ctx, 1, 0);

}


static int piv_finish(sc_card_t *card)
{
 	struct piv_private_data * priv = (struct piv_private_data *) card->drv_data;

	SC_FUNC_CALLED(card->ctx,1);
	if (priv) {
		if (priv->aid_file)
			sc_file_free(priv->aid_file);
		free(priv);
	}
	return 0;
}


static int piv_match_card(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx,1);
	/* dee need to look at AID */
	return 0; /* never match */
}


static int piv_init(sc_card_t *card)
{
	int r;
	unsigned long flags;
	struct piv_private_data *priv;

	SC_FUNC_CALLED(card->ctx,1);
	priv = (struct piv_private_data *) calloc(1, sizeof(struct piv_private_data));

	if (!priv)
		return SC_ERROR_OUT_OF_MEMORY;
	priv->aid_file = sc_file_new();
	priv->selected_obj = -1;
	priv->max_recv_size = card->max_recv_size;
	priv->max_send_size = card->max_send_size;
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
	SC_FUNC_RETURN(card->ctx, 1, r);
}


static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	piv_ops = *iso_drv->ops;
	piv_ops.match_card = piv_match_card;
	piv_ops.init = piv_init;
	piv_ops.finish = piv_finish;
	
	piv_ops.select_file =  piv_select_file; /* must use get/put, could emulate? */
	piv_ops.logout = piv_logout;
	piv_ops.get_challenge = piv_get_challenge;
	piv_ops.read_binary = piv_read_binary;
	piv_ops.write_binary = piv_write_binary;
	piv_ops.set_security_env = piv_set_security_env;
	piv_ops.restore_security_env = piv_restore_security_env;
	piv_ops.compute_signature = piv_compute_signature;
	piv_ops.decipher =  piv_decipher;
	piv_ops.card_ctl = piv_card_ctl;

	return &piv_drv;
}


#if 1
struct sc_card_driver * sc_get_piv_driver(void)
{
	return sc_get_driver();
}
#endif
