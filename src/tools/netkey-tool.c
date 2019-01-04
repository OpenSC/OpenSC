/*
 * Netkey-Tool for Telesec Netkey E4 cards.
 *
 * Copyright (C) 2005, Peter Koch <pk_opensc@web.de>
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "common/compat_getopt.h"
#include "libopensc/opensc.h"

static struct {
	const char *path;
	int   readonly;
	const char *label;
} certlist[]={
	{"DF01C000", 1, "Telesec Signatur Zertifikat"},
	{"DF014331", 0, "User Signatur Zertifikat1"},
	{"DF014332", 0, "User Signatur Zertifikat2"},
	{"DF01C100", 1, "Telesec Authentifizierungs Zertifikat"},
	{"DF014371", 0, "User Authentifizierungs Zertifikat1"},
	{"DF014372", 0, "User Authentifizierungs Zertifikat2"},
	{"DF01C200", 1, "Telesec Verschluesselungs Zertifikat"},
	{"DF0143B1", 0, "User Verschluesselungs Zertifikat1"},
	{"DF0143B2", 0, "User Verschluesselungs Zertifikat2"},
};

static struct {
	const char *path;
	const char *name;
	const char *label;
	int   p1, p2;
	int   tries;
	size_t len;
	u8    value[32];
} pinlist[]={
	{"3F005000",     "pin",  "global PIN",  1,-1, 0, 0,
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	{"3F005001",     "puk",  "global PUK", -1,-1, 0, 0,
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	{"3F00DF015080", "pin0", "local PIN0",  3, 0, 0, 0,
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	{"3F00DF015081", "pin1", "local PIN1",  0,-1, 0, 0,
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
};


static void show_pin(sc_card_t *card, int pin)
{
	sc_path_t p;
	sc_file_t *f;
	struct sc_apdu a;
	int i, max;

	sc_format_path(pinlist[pin].path,&p);
	if((i=sc_select_file(card,&p,&f))<0){
		printf("\nCannot select PIN-file %s, is this a NetKey-Card ??\n", pinlist[pin].path);
		return;
	}
	if(f->type!=SC_FILE_TYPE_WORKING_EF || f->ef_structure!=SC_FILE_EF_LINEAR_VARIABLE_TLV ||
	   f->prop_attr_len!=5 || f->prop_attr[0]!=0x01 || f->prop_attr[1]!=0x80
	){
		printf("\nInvalid PIN-file: Type=%d, EF-Structure=%d, Prop-Len=%lu %02X:%02X:%02X\n",
			f->type, f->ef_structure, (unsigned long) f->prop_attr_len,
			f->prop_attr[0], f->prop_attr[1], f->prop_attr[2]
		);
		return;
	}
	pinlist[pin].tries=f->prop_attr[3], max=f->prop_attr[4];

	if(pinlist[pin].len){
		sc_format_apdu(card, &a, SC_APDU_CASE_3_SHORT, 0x20, 0x00, f->prop_attr[2] | (pin>1 ? 0x80 : 0x00) );
		a.data=pinlist[pin].value, a.lc=a.datalen=pinlist[pin].len;
	} else {
		sc_format_apdu(card, &a, SC_APDU_CASE_1, 0x20, 0x00, f->prop_attr[2] | (pin>1 ? 0x80 : 0x00) );
	}
	if((i=sc_transmit_apdu(card, &a))<0){
		printf("\nsc_transmit_apdu() failed, %s\n", sc_strerror(i));
		return;
	}
	printf("%s: %d tries left, %d tries max, ", pinlist[pin].label, pinlist[pin].tries, max);
	if(a.sw1==0x63 && (a.sw2&0xF0)==0xC0) printf("not verified\n");
	else if(a.sw1==0x90 && a.sw2==0x00) printf("verified\n");
	else if(a.sw1==0x69 && a.sw2==0x83) printf("blocked\n");
	else if(a.sw1==0x69 && a.sw2==0x85) printf("NullPin\n");
	else printf("Error %02X%02X\n", a.sw1, a.sw2);
}

static void show_certs(sc_card_t *card)
{
	sc_path_t p;
	sc_file_t *f;
	X509 *c;
	u8 buf[2000];
	const u8 *q;
	int j;
	size_t i;

	printf("\n");
	for(i=0;i<sizeof(certlist)/sizeof(certlist[0]);++i){
		printf("Certificate %lu: %s",
			(unsigned long) i, certlist[i].label); fflush(stdout);

		sc_format_path(certlist[i].path,&p);
		if((j=sc_select_file(card,&p,&f))<0){
			printf(", Cannot select Cert-file %s, is this a NetKey-Card ??\n",
				certlist[i].path
			);
			continue;
		}
		if(f->type!=SC_FILE_TYPE_WORKING_EF || f->ef_structure!=SC_FILE_EF_TRANSPARENT){
			printf(", Invalid Cert-file: Type=%d, EF-Structure=%d\n", f->type, f->ef_structure);
			continue;
		}
		if((j=sc_read_binary(card,0,buf,f->size,0))<0){
			printf(", Cannot read Cert-file, %s\n", sc_strerror(j));
			continue;
		}
		printf(", Maxlen=%lu", (unsigned long) f->size);
		q=buf;
		if(q[0]==0x30 && q[1]==0x82){
			if(q[4]==6 && q[5]<10 && q[q[5]+6]==0x30 && q[q[5]+7]==0x82) q+=q[5]+6;
			printf(", Len=%d\n", (q[2]<<8)|q[3]);
			if((c=d2i_X509(NULL,&q,f->size))){
				char buf2[2000];
				X509_NAME_get_text_by_NID(X509_get_subject_name(c), NID_commonName, buf2,sizeof(buf2));
				printf("  Subject-CN: %s\n", buf2);
				X509_NAME_get_text_by_NID(X509_get_issuer_name(c), NID_commonName, buf2,sizeof(buf2));
				printf("  Issuer-CN:  %s\n", buf2);
				X509_free(c);
			} else printf("  Invalid Certificate-Data\n");
		} else printf(", empty\n");
	}
}

static void show_initial_puk(sc_card_t *card)
{
	sc_path_t p;
	sc_file_t *f;
	struct sc_apdu a;
	u8 buf1[128], buf2[128];
	int i;

	printf("\nReading crypted Initial-PUK-file: ");
	sc_format_path("3F004350",&p);
	if((i=sc_select_file(card,&p,&f))<0){
		printf("Cannot select crypted Initial-PUK-file, %s\n", sc_strerror(i));
		return;
	}
	if((i=sc_read_binary(card,0,buf1,128,0))!=128){
		printf("Cannot read crypted Initial-PUK-file, %s\n", sc_strerror(i));
		return;
	}

	printf("OK\nDecrypting crypted Initial-PUK-file: ");
	sc_format_path("3F00DF01",&p);
	if((i=sc_select_file(card,&p,&f))<0){
		printf("Cannot select DF01, %s\n", sc_strerror(i));
		return;
	}
	sc_format_apdu(card, &a, SC_APDU_CASE_3_SHORT, 0x22, 0xC1, 0xB8);
	buf2[0]=0x80, buf2[1]=0x01, buf2[2]=0x10, buf2[3]=0x84, buf2[4]=0x01, buf2[5]=0x81;
	a.data=buf2, a.lc=a.datalen=6;
	if((i=sc_transmit_apdu(card, &a))<0){
		printf("sc_transmit_apdu(MSE) failed, %s\n", sc_strerror(i));
		return;
	}
	if(a.sw1!=0x90 && a.sw2!=0x00){
		printf("MSE=%02X%02X\n", a.sw1, a.sw2);
		return;
	}
	sc_format_apdu(card, &a, SC_APDU_CASE_4_SHORT, 0x2A, 0x84, 0x80);
	a.data=buf1, a.lc=a.datalen=128;
	a.resp=buf2, a.le=a.resplen=128;
	if((i=sc_transmit_apdu(card, &a))<0){
		printf("sc_transmit_apdu(PSO) failed, %s\n", sc_strerror(i));
		return;
	}
	if(a.sw1!=0x90 && a.sw2!=0x00){
		printf("PSO=%02X%02X\n", a.sw1, a.sw2);
		return;
	}
	printf("OK ==> Initial-PUK:"); for(i=120;i<128;++i) printf("%c",buf2[i]); printf("\n");
}

static void show_card(sc_card_t    *card)
{
	sc_path_t path;
	sc_file_t *file;
	u8 buf[100];
	int i, len;

	sc_format_path("3F002F02",&path);
	if((i=sc_select_file(card,&path,&file))<0){
		printf("\nCannot select Serial-Number 2F02, is this a NetKey-Card ??\n");
		return;
	}
	if(file->type!=SC_FILE_TYPE_WORKING_EF || file->ef_structure!=SC_FILE_EF_TRANSPARENT ||
	   file->size!=12 || (len=sc_read_binary(card,0,buf,12,0))!=12 || buf[0]!=0x5A || buf[1]!=0x0A
	){
		printf("\nInvalid Serial-Number: Type=%d, EF-Structure=%d, Size=%lu\n",
			file->type, file->ef_structure, (unsigned long) file->size
		);
		return;
	}
	printf("\nSerial-Number: ");
	for(i=2;i<11;++i) printf("%02X", buf[i]);
	printf("%X\n\n", buf[11]>>4);

	for(i=0;i<4;++i) show_pin(card, i);
	/* printf("%s: %u tries left, %u tries max, %s\n", pinlist[i].label, pinlist[i].tries, max, status); */

	if(pinlist[0].len) show_initial_puk(card);
}


static void handle_change( sc_card_t *card, int        pin1, int        pin2,
	int        do_change, u8        *newpin, int        newlen)
{
	sc_path_t p;
	sc_file_t *f;
	struct sc_apdu a;
	u8 ref;
	int i;

	printf("\n%s %s with %s: ", do_change ? "Changing" : "Unblocking", pinlist[pin1].label, pinlist[pin2].label);

	sc_format_path(pinlist[pin1].path,&p);
	if((i=sc_select_file(card,&p,&f))<0){
		printf("\nCannot select %s, %s\n", pinlist[pin1].label, sc_strerror(i));
		return;
	}
	ref=f->prop_attr[2] | (strlen(pinlist[pin1].path)>8 ? 0x80 : 0x00);

	if(do_change){
		sc_format_apdu(card, &a, SC_APDU_CASE_3_SHORT, 0x24, 0x01, ref);
		a.data=newpin, a.lc=a.datalen=newlen;
	} else {
		sc_format_apdu(card, &a, SC_APDU_CASE_1, 0x2C, 0x03, ref);
	}
	if((i=sc_transmit_apdu(card, &a))<0){
		printf("\nsc_transmit_apdu() failed, %s\n", sc_strerror(i));
		return;
	}
	if(a.sw1!=0x90 && a.sw2!=0x00){
		printf("%02X%02X\n", a.sw1, a.sw2);
		return;
	}
	printf("OK\n");
}


static void handle_nullpin(sc_card_t *card, u8 *newpin, int newlen)
{
	sc_path_t p;
	sc_file_t *f;
	struct sc_apdu a;
	u8 ref, buf[40];
	int i;

	printf("\nSetting initial PIN-value: ");

	sc_format_path(pinlist[0].path,&p);
	if((i=sc_select_file(card,&p,&f))<0){
		printf("\nCannot select %s, %s\n", pinlist[0].label, sc_strerror(i));
		return;
	}
	ref=f->prop_attr[2];

	sc_format_apdu(card, &a, SC_APDU_CASE_1, 0x20, 0x00, f->prop_attr[2]);
	if((i=sc_transmit_apdu(card, &a))<0){
		printf("sc_transmit_apdu() failed, %s\n", sc_strerror(i));
		return;
	}
	if(a.sw1!=0x69 && a.sw2!=0x85){
		printf("global PIN is not in NullPin-state (%02X%02X)\n", a.sw1, a.sw2);
		return;
	}

	sc_format_apdu(card, &a, SC_APDU_CASE_3_SHORT, 0x24, 0x00, ref);
	for(i=0;i<6;++i) buf[i]=0;
	for(i=0;i<newlen;++i) buf[6+i]=newpin[i];
	a.data=buf, a.lc=a.datalen=6+newlen;
	if((i=sc_transmit_apdu(card, &a))<0){
		printf("sc_transmit_apdu() failed, %s\n", sc_strerror(i));
		return;
	}
	if(a.sw1!=0x90 && a.sw2!=0x00){
		printf("Error %02X%02X\n", a.sw1, a.sw2);
		return;
	}
	printf("OK\n");
}


static void handle_readcert(sc_card_t *card, int cert, char *file)
{
	sc_path_t p;
	sc_file_t *f;
	FILE *fp;
	X509 *c;
	u8 buf[1536];
	const u8 *q;
	int i, len;

	printf("\nReading Card-Certificate %d: ", cert); fflush(stdout);

	sc_format_path(certlist[cert].path,&p);
	if((i=sc_select_file(card,&p,&f))<0){
		printf("cannot select certfile, %s\n", sc_strerror(i));
		return;
	}
	if((len=sc_read_binary(card,0,buf,f->size,0))<0){
		printf("Cannot read Cert, %s\n", sc_strerror(len));
		return;
	}
	q=buf;
	if(q[0]==0x30 && q[1]==0x82 && q[4]==6 && q[5]<10 && q[q[5]+6]==0x30 && q[q[5]+7]==0x82) q+=q[5]+6;
	if((c=d2i_X509(NULL,&q,len))==NULL){
		printf("cardfile contains %d bytes which are not a certificate\n", len);
		return;
	}
	printf("Writing Cert to %s: ", file); fflush(stdout);
	if((fp=fopen(file,"w"))==NULL) printf("Cannot open file, %s\n", strerror(errno));
	else {
		fprintf(fp,"Certificate %d from Netkey E4 card\n\n", cert);
		PEM_write_X509(fp,c);
		printf("OK\n");
	}
	X509_free(c);
}


static void handle_writecert(sc_card_t *card, int cert, char *file)
{
	sc_path_t p;
	sc_file_t *f;
	FILE *fp;
	X509 *c;
	u8 buf[1536], *q;
	int i, len;

	printf("\nReading Cert from %s: ", file); fflush(stdout);

	if((fp=fopen(file,"r"))==NULL){
		printf("Cannot open file, %s\n", strerror(errno));
		return;
	}
	c=PEM_read_X509(fp,NULL,NULL,NULL);
	fclose(fp);
	if(c==NULL){
		printf("file does not conatin PEM-encoded certificate\n");
		return;
	}
	printf("OK\nStoring Cert into Card-Certificate %d: ", cert); fflush(stdout);
	q=buf;
	len=i2d_X509(c,NULL);
	if(len>0 && len<=(int)sizeof(buf))
		i2d_X509(c,&q);
	X509_free(c);
	if(len<=0 || len>(int)sizeof(buf)){
		printf("certificate too long or invalid (Len=%d)\n", len);
		return;
	}

	sc_format_path(certlist[cert].path,&p);
	if((i=sc_select_file(card,&p,&f))<0){
		printf("cannot select certfile, %s\n", sc_strerror(i));
		return;
	}
	if((i=sc_update_binary(card,0,buf,len,0))<0){
		printf("cannot store cert, %s\n", sc_strerror(i));
		return;
	}
	printf("OK\n");
}


static int pin_string2int(char *s) {
	size_t i;

	for(i=0;i<sizeof(pinlist)/sizeof(pinlist[0]);++i) if(!strcasecmp(pinlist[i].name,s)) return i;
	return -1;
}

static void set_pin(u8 *data, size_t *pinlen, char *pin)
{
	int hex;
	size_t i, len;

	len=strlen(pin);
	hex=(len>=5 && len%3==2);
	if(hex){
		*pinlen = sizeof (pinlist[0].value);
		sc_hex_to_bin(pin, data, pinlen);
	} else {
		len=strlen(pin); if(len>32) len=32;
		for(i=0;i<len;++i) data[i]=((u8*)pin)[i];
		*pinlen=len;
	}
}



int main(
	int   argc,
	char *argv[]
){
	const struct option options[]={
		{ "help",     0, NULL, 'h' },
		{ "verbose",  0, NULL, 'v' },
		{ "reader",   1, NULL, 'r' },
		{ "pin",      1, NULL, 'p' },
		{ "puk",      1, NULL, 'u' },
		{ "pin0",     1, NULL, '0' },
		{ "pin1",     1, NULL, '1' },
		{ NULL, 0, NULL, 0 }
	};
	sc_context_t *ctx;
	sc_context_param_t ctx_param;
	sc_card_t *card;
	int do_help=0, do_unblock=0, do_change=0, do_nullpin=0, do_readcert=0, do_writecert=0;
	u8 newpin[32];
	char *certfile=NULL, *p;
	int r, oerr=0, reader=0, debug=0, pin_nr=-1, cert_nr=-1;
	size_t i, newlen=0;

	while((r=getopt_long(argc,argv,"hvr:p:u:0:1:",options,NULL))!=EOF) switch(r){
		case 'h': ++do_help; break;
		case 'v': ++debug; break;
		case 'r': reader=atoi(optarg); break;
		case 'p': set_pin(pinlist[0].value, &pinlist[0].len, optarg); break;
		case 'u': set_pin(pinlist[1].value, &pinlist[1].len, optarg); break;
		case '0': set_pin(pinlist[2].value, &pinlist[2].len, optarg); break;
		case '1': set_pin(pinlist[3].value, &pinlist[3].len, optarg); break;
		default: ++oerr;
	}
	if(do_help){
		fprintf(stderr,"This is netkey-tool V1.0, May 15 2005, Copyright Peter Koch <pk_opensc@web.de>\n");
		fprintf(stderr,"usage: %s <options> command\n", argv[0]);
		fprintf(stderr,"\nOptions:\n");
		fprintf(stderr,"  -v                       : verbose, may be specified several times\n");
		fprintf(stderr,"  --reader <num>, -r <num> : use reader num (default 0)\n");
		fprintf(stderr,"  --pin <pin>, -p <pin>    : current value of global PIN\n");
		fprintf(stderr,"  --puk <pin>, -u <pin>    : current value of global PUK\n");
		fprintf(stderr,"  --pin0 <pin>, -0 <pin>   : current value of local PIN0\n");
		fprintf(stderr,"  --pin1 <pin>, -1 <pin>   : current value of local PIN1\n");
		fprintf(stderr,"\nCommands:\n");
		fprintf(stderr,"  unblock {pin | pin0 | pin1}\n");
		fprintf(stderr,"  change {pin | puk | pin0 | pin1} <new pin>\n");
		fprintf(stderr,"  nullpin <new pin>\n");
		fprintf(stderr,"  cert <certnum> <filepath>\n");
		fprintf(stderr,"  cert <filepath> <certnum>\n");
		fprintf(stderr,"\nExamples:\n");
		fprintf(stderr,"list PINs and Certs without changing anything. Try this first!!\n");
		fprintf(stderr,"  %s\n", argv[0]);
		fprintf(stderr,"\nlist PINs and Certs and initial PUK-value (after verification of global PIN)\n");
		fprintf(stderr,"  %s --pin 123456\n", argv[0]);
		fprintf(stderr,"\nchange local PIN0 to 654321 after verification of global PIN\n");
		fprintf(stderr,"  %s --pin 123456 change pin0 654321\n", argv[0]);
		fprintf(stderr,"\nchange global PIN from hex 01:02:03:04:05:06 to ascii 123456\n");
		fprintf(stderr,"  %s --pin 01:02:03:04:05:06 change pin 123456\n", argv[0]);
		fprintf(stderr,"\nunblock global PIN with global PUK\n");
		fprintf(stderr,"  %s --puk 12345678 unblock pin\n", argv[0]);
		fprintf(stderr,"\nset global PIN to initial value when in NullPin-state\n");
		fprintf(stderr,"  %s nullpin 123456\n", argv[0]);
		fprintf(stderr,"\nstore Certificate into card at position 2 and read it back into file\n");
		fprintf(stderr,"  %s --pin1 123456 cert /tmp/cert1 2\n", argv[0]);
		fprintf(stderr,"  %s cert 2 /tmp/cert2\n", argv[0]);
		fprintf(stderr,"\nBe careful - this tool may destroy your card\n");
		fprintf(stderr,"\nQuestions? Comments? ==> opensc-user@opensc-project.org\n");
		exit(1);
	}
	if(optind==argc-2 && !strcmp(argv[optind],"unblock")){
		++optind, do_unblock=1;
		pin_nr=pin_string2int(argv[optind++]);
		if(pin_nr<0 || pin_nr==1) ++oerr;
	}
	if(optind==argc-3 && !strcmp(argv[optind],"change")){
		++optind, do_change=1;
		pin_nr=pin_string2int(argv[optind++]);
		if(pin_nr<0 || pin_nr>3) ++oerr;
		set_pin(newpin,&newlen,argv[optind++]);
	}
	if(optind==argc-2 && !strcmp(argv[optind],"nullpin")){
		++optind, do_nullpin=1;
		set_pin(newpin,&newlen,argv[optind++]);
	}
	if(optind==argc-3 && !strcmp(argv[optind],"cert")){
		++optind;
		cert_nr=strtol(argv[optind],&p,10);
		if(argv[optind][0] && !*p && cert_nr>=0 && cert_nr<(int)(sizeof(certlist)/sizeof(certlist[0]))){
			do_readcert=1, certfile=argv[optind+1];
		} else {
			do_writecert=1, certfile=argv[optind];
			cert_nr=strtol(argv[optind+1],&p,10);
			if(!argv[optind][0] || *p || cert_nr<0 || cert_nr>=(int)(sizeof(certlist)/sizeof(certlist[0]))) ++oerr;
		}
		optind+=2;
	}
	if(oerr || optind!=argc){
		fprintf(stderr,"%s: invalid usage, try --help\n", argv[0]);
		exit(1);
	}

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = argv[0];

	r = sc_context_create(&ctx, &ctx_param);
	if(r < 0){
		fprintf(stderr,"Establish-Context failed: %s\n", sc_strerror(r));
		exit(1);
	}
	if(ctx->debug>0)
		printf("Context for application \"%s\" created, Debug=%d\n", ctx->app_name, ctx->debug);

	for(i=0;ctx->card_drivers[i];++i)
		if(!strcmp("tcos", ctx->card_drivers[i]->short_name)) break;
	if(!ctx->card_drivers[i]){
		fprintf(stderr,"Context does not support TCOS-cards\n");
		exit(1);
	}

	printf("%d Readers detected\n", sc_ctx_get_reader_count(ctx));
	if(reader < 0 || reader >= (int)sc_ctx_get_reader_count(ctx)){
		fprintf(stderr,"Cannot open reader %d\n", reader);
		exit(1);
	}

	if((r = sc_connect_card(sc_ctx_get_reader(ctx, 0), &card))<0){
		fprintf(stderr,"Connect-Card failed: %s\n", sc_strerror(r));
		exit(1);
	}
	printf("\nCard detected (driver: %s)\nATR:", card->driver->name);
	for (i = 0; i < card->atr.len; ++i)
		printf("%c%02X", i?':':' ', card->atr.value[i]);
	printf("\n");

	if((r = sc_lock(card))<0){
		fprintf(stderr,"Lock failed: %s\n", sc_strerror(r));
		exit(1);
	}

	show_card(card);

	if(do_unblock || do_change){
		int i1=pinlist[pin_nr].p1, i2=pinlist[pin_nr].p2;

		if((do_unblock || !pinlist[pin_nr].len) &&
		   (i1<0 || !pinlist[i1].len) && (i2<0 || !pinlist[i2].len)
		){
			fprintf(stderr, "\nNeed %s", do_change ? pinlist[pin_nr].label : pinlist[i1].label);
			if(do_change && i1>=0) fprintf(stderr, " or %s", pinlist[i1].label);
			if(i2>=0) fprintf(stderr, " or %s", pinlist[i2].label);
			fprintf(stderr, " to %s %s\n", do_change ? "change" : "unblock", pinlist[pin_nr].label);
		} else {
			if(do_change && pinlist[pin_nr].len) i1=pin_nr;
			if(i1<0 || !pinlist[i1].len) i1=i2;
			handle_change(card, pin_nr, i1, do_change, newpin, newlen);
		}
	}

	if(do_nullpin){
		handle_nullpin(card, newpin, newlen);
		show_initial_puk(card);
	}

	if(do_readcert) handle_readcert(card, cert_nr, certfile);
	if(do_writecert){
		if(certlist[cert_nr].readonly){
			fprintf(stderr, "\nReadonly-Certificate %d cannot be changed\n", cert_nr);
		} else if(!pinlist[0].len && !pinlist[3].len){
			fprintf(stderr, "\nNeed %s or %s to change Card-Certificate %d\n",
				pinlist[0].label, pinlist[3].label, cert_nr
			);
		} else handle_writecert(card, cert_nr, certfile);
	}

	if(do_unblock+do_change+do_nullpin+do_readcert==0) show_certs(card);

	sc_unlock(card);
	sc_disconnect_card(card);
	sc_release_context(ctx);

	exit(0);
}
