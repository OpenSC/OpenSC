#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>

int quiet = 0;
char *opt_outfile = NULL;
char *opt_cert = NULL;

const struct option options[] = {
	{ "extract-key",	0, 0,		'k' },
	{ "certificate-id",	1, 0,		'c' },
	{ "reader",		1, 0,		'r' },
	{ "output",		1, 0,		'o' },
	{ "quiet",		0, 0,		'q' },

	{ 0, 0, 0, 0 }
};

const char *option_help[] = {
	"Extracts the public key from a certificate",
	"Uses certificate with ID <arg>",
	"Uses reader number <arg>",
	"Outputs to file <arg>",
	"Quiet operation",
};

struct sc_context *ctx = NULL;
struct sc_card *card = NULL;
struct sc_pkcs15_card *p15card = NULL;

void print_usage_and_die(void)
{
	int i = 0;
	printf("Usage: opensc-ssh [OPTIONS]\nOptions:\n");

	while (options[i].name) {
		char buf[40], tmp[5];
		const char *arg_str;
		
		if (options[i].val > 0 && options[i].val < 128)
			sprintf(tmp, ", -%c", options[i].val);
		else
			tmp[0] = 0;
		switch (options[i].has_arg) {
		case 1:
			arg_str = " <arg>";
			break;
		case 2:
			arg_str = " [arg]";
			break;
		default:
			arg_str = "";
			break;
		}
		sprintf(buf, "--%s%s%s", options[i].name, tmp, arg_str);
		printf("  %-30s%s\n", buf, option_help[i]);
		i++;
	}
	exit(2);
}

u8 * bignum_to_buf(BIGNUM *value, int *length, int *skip)
{
	/* Function ripped from bufaux.c in OpenSSH
	 * Compliments to Tatu Ylönen */
        int bytes = BN_num_bytes(value) + 1;
        u8 *buf = (u8 *) malloc(bytes);
        int oi;
        int hasnohigh = 0;
        buf[0] = '\0';

	if (buf == NULL)
		return NULL;
        /* Get the value of in binary */
        oi = BN_bn2bin(value, buf+1);
        if (oi != bytes-1)
        	return NULL;
        hasnohigh = (buf[1] & 0x80) ? 0 : 1;
        if (value->neg) {
                /**XXX should be two's-complement */
                int i, carry;
                u_char *uc = buf;
                for(i = bytes-1, carry = 1; i>=0; i--) {
                        uc[i] ^= 0xff;
                        if(carry)
                                carry = !++uc[i];
                }
        }
	*skip = hasnohigh;
	*length = bytes;
	
	return buf;
}

int put_string(const u8 *in, int inlen, u8 *out, int outlen, int *skip)
{
	u8 *out0 = out;
	
	if (outlen < 4 + inlen)
		return -1;
	*out++ = (inlen >> 24) & 0xFF;
	*out++ = (inlen >> 16) & 0xFF;
	*out++ = (inlen >> 8) & 0xFF;
	*out++ = (inlen) & 0xFF;
	memcpy(out, in, inlen);
	out += inlen;
	
	*skip = out - out0;
	
	return 0;
}

int write_ssh_key(struct sc_pkcs15_cert_info *cinfo, RSA *rsa)
{
	u8 *buf = (u8 *) malloc(10240), *p = buf, *num;
	int r, len, skip, left = 10240;
	FILE *outf;
	
	if (buf == NULL)
		return 1;
	put_string((u8 *) "ssh-rsa", 7, p, left, &skip);
	left -= skip;
	p += skip;
	num = bignum_to_buf(rsa->e, &len, &skip);
	if (num == NULL)
		return 1;
	put_string(num+skip, len-skip, p, left, &skip);
	left -= skip;
	p += skip;
	free(num);
	num = bignum_to_buf(rsa->n, &len, &skip);
	if (num == NULL)
		return 1;
	put_string(num+skip, len-skip, p, left, &skip);
	left -= skip;
	p += skip;
	free(num);

	len = p - buf;
	p = (u8 *) malloc(len*5/3);
	r = sc_base64_encode(buf, len, p, len*5/3, 0);
	if (r) {
		fprintf(stderr, "Base64 encoding failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (opt_outfile == NULL)
		outf = stdout;
	else {
		outf = fopen(opt_outfile, "w");
		if (outf == NULL) {
			fprintf(stderr, "Unable to open '%s' for writing.\n",
				opt_outfile);
			return 2;
		}
	}
	fprintf(outf, "ssh-rsa %s opensc-cert-%02X\n", p, cinfo->id.value[0]);
	free(p),
	free(buf);
	return 0;
}

int extract_key(void)
{
	int r, i, count;
	struct sc_pkcs15_id id;
	u8 *p = id.value;
	char *certp = opt_cert;
	struct sc_pkcs15_cert *cert;
	struct sc_pkcs15_object *objs[32];
	struct sc_pkcs15_cert_info *cinfo = NULL;
	X509 *x509;
	EVP_PKEY *pubkey;
	
	if (opt_cert) {
		if (((strlen(opt_cert)/2) >= SC_PKCS15_MAX_ID_SIZE)) {
			fprintf(stderr, "Certificate id too long.\n");
			return 2;
		}
		id.len = 0;
		while (*certp) {
			int byte;
	
			if (sscanf(certp, "%02X", &byte) != 1)
				break;
			certp += 2;
			*p = byte;
			p++;
			id.len++;
		}
	}
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	count = r;
	if (opt_cert) {
		for (i = 0; i < count; i++) {
			cinfo = (struct sc_pkcs15_cert_info *) objs[i]->data;
	
			if (sc_pkcs15_compare_id(&id, &cinfo->id) == 1)
				break;
		}
		if (i == count) {
			fprintf(stderr, "Certificate with ID '%s' not found.\n", opt_cert);
			return 2;
		}
	} else {
		i = 0;
		cinfo = (struct sc_pkcs15_cert_info *) objs[i]->data;
	}
	if (!quiet)
		fprintf(stderr, "Using certificate '%s'.\n", objs[i]->label);
	r = sc_pkcs15_read_certificate(p15card, cinfo, &cert);
	if (r) {
		fprintf(stderr, "Certificate read failed: %s\n", sc_strerror(r));
		return 1;
	}
	x509 = X509_new();
	p = cert->data;
	if (!d2i_X509(&x509, &p, cert->data_len)) {
		fprintf(stderr, "Unable to parse X.509 certificate.\n");
		return 1;
	}
	pubkey = X509_get_pubkey(x509);
	if (pubkey->type != EVP_PKEY_RSA) {
		fprintf(stderr, "Public key is of unknown type.\n");
		return 1;
	}
	r = write_ssh_key(cinfo, pubkey->pkey.rsa);
	EVP_PKEY_free(pubkey);
	X509_free(x509);
	
	return r;
}

int main(int argc, char *const argv[])
{
	int err = 0, r, c, long_optind = 0;
	int action_count = 0, do_extract_key = 0;
	int opt_reader = 0;

	while (1) {
		c = getopt_long(argc, argv, "r:o:qkc:", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			continue;
		switch (c) {
		case 'k':
			do_extract_key = 1;
			action_count++;
			break;
		case 'c':
			opt_cert = optarg;
			break;
		case 'r':
			opt_reader = atoi(optarg);
			break;
		case 'o':
			opt_outfile = optarg;
			break;
		case 'q':
			quiet++;
			break;
		}
	}
	if (action_count == 0)
		print_usage_and_die();
	r = sc_establish_context(&ctx, "opensc-ssh");
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}
	if (opt_reader >= ctx->reader_count || opt_reader < 0) {
		fprintf(stderr, "Illegal reader number. Only %d reader(s) configured.\n", ctx->reader_count);
		err = 1;
		goto end;
	}
	if (sc_detect_card_presence(ctx->reader[opt_reader], 0) != 1) {
		fprintf(stderr, "Card not present.\n");
		return 3;
	}
	if (!quiet)
		fprintf(stderr, "Connecting to card in reader %s...\n", ctx->reader[opt_reader]->name);
	r = sc_connect_card(ctx->reader[opt_reader], 0, &card);
	if (r) {
		fprintf(stderr, "Failed to connect to card: %s\n", sc_strerror(r));
		err = 1;
		goto end;
	}

	sc_lock(card);
	if (!quiet)
		fprintf(stderr, "Trying to find a PKCS#15 compatible card...\n");
	r = sc_pkcs15_bind(card, &p15card);
	if (r) {
		fprintf(stderr, "PKCS#15 initialization failed: %s\n", sc_strerror(r));
		err = 1;
		goto end;
	}
	if (!quiet)
		fprintf(stderr, "Found %s!\n", p15card->label);
	if (do_extract_key) {
		if ((err = extract_key()))
			goto end;
		action_count--;
	}

end:
	if (p15card)
		sc_pkcs15_unbind(p15card);
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card, 0);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}
