
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sc.h>
#include <sc-pkcs15.h>

#define OPT_CHANGE_PIN	0x100
#define OPT_LIST_PINS	0x101
#define OPT_READER	0x102

int opt_reader = 0, opt_pin = 0;
char * opt_cert = NULL;
char * opt_outfile = NULL;
char * opt_pincode = NULL;
char * opt_newpin = NULL;
int quiet = 0;

const struct option options[] = {
	{ "list-readers",	0, 0, 		'l' },
	{ "list-files",		0, 0,		'f' },
	{ "read-certificate",	1, 0, 		'r' },
	{ "list-certificates",	0, 0,		'c' },
	{ "list-pins",		0, 0,		OPT_LIST_PINS },
	{ "change-pin",		2, 0,		OPT_CHANGE_PIN },
	{ "reader",		1, 0,		OPT_READER },
	{ "output",		1, 0,		'o' },
	{ "quiet",		0, 0,		'q' },
	{ "pin",		1, 0,		'p' },
	{ "pin-id",		1, &opt_pin,	0   },
	{ 0, 0, 0, 0 }
};

const char *option_help[] = {
	"Lists all configured readers",
	"Recursively lists files stored on card",
	"Read certificate with ID <arg>",
	"Lists certificates",
	"Lists PIN codes",
	"Changes the PIN code to <arg>",
	"Uses reader number <arg>",
	"Outputs to file <arg>",
	"Quiet operation",
	"Uses PIN <arg>; if not supplied, asks the user",
	"Choose which PIN to use",
};

struct sc_context *ctx = NULL;
struct sc_card *card = NULL;
struct sc_pkcs15_card *p15card = NULL;

void print_usage_and_die()
{
	int i = 0;
	printf("Usage: sc-tool [OPTIONS]\nOptions:\n");

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

int list_readers()
{
	int i;
	
	printf("Configured readers:\n");
	for (i = 0; i < ctx->reader_count; i++) {
		printf("\t%d - %s\n", i, ctx->readers[i]);
	}
	return 0;
}

int list_certificates()
{
	int r, i;
	
	r = sc_pkcs15_enum_certificates(p15card);
	if (r < 0) {
		fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (!quiet)
		printf("Card has %d certificate(s).\n\n", p15card->cert_count);
	for (i = 0; i < p15card->cert_count; i++) {
		struct sc_pkcs15_cert_info *cinfo = &p15card->cert_info[i];
		sc_pkcs15_print_cert_info(cinfo);
		printf("\n");
	}
	return 0;
}

int read_certificate()
{
	int r, i;
	struct sc_pkcs15_id id;
	u8 *p = id.value;
	char *certp = opt_cert;
	FILE *outf;

	if (strlen(opt_cert)/2 >= SC_PKCS15_MAX_ID_SIZE) {
		fprintf(stderr, "Certificate id too long.\n");
		return 2;
	}
	if (!quiet)
		printf("Reading certificate with ID '%s'\n", opt_cert);
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
	r = sc_pkcs15_enum_certificates(p15card);
	if (r < 0) {
		fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	for (i = 0; i < p15card->cert_count; i++) {
		struct sc_pkcs15_cert_info *cinfo = &p15card->cert_info[i];
		struct sc_pkcs15_cert *cert;
		u8 buf[2048];

		if (sc_pkcs15_compare_id(&id, &cinfo->id) != 1)
			continue;
			
		r = sc_pkcs15_read_certificate(p15card, cinfo, &cert);
		if (r) {
			fprintf(stderr, "Certificate read failed: %s\n", sc_strerror(r));
			return 1;
		}
		r = sc_base64_encode(cert->data, cert->data_len, buf,
				     sizeof(buf), 64);
		sc_pkcs15_free_certificate(cert);
		if (r) {
			fprintf(stderr, "Base64 encoding failed: %s\n", sc_strerror(r));
			return 1;
		}
		if (opt_outfile != NULL) {
			outf = fopen(opt_outfile, "w");
			if (outf == NULL) {
				fprintf(stderr, "Error opening file '%s': %s\n",
					opt_outfile, strerror(errno));
				return 2;
			}
		} else
			outf = stdout;
		fprintf(outf, "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n",
			buf);
		if (outf != stdout)
			fclose(outf);
	}
	return 0;
}

const char * get_pin()
{
	int r;
	char buf[80];
	char *pincode;
	struct sc_pkcs15_pin_info *pinfo;
	
	if (opt_pincode != NULL)
		return opt_pincode;

	r = sc_pkcs15_enum_pins(p15card);
	if (r < 0) {
		fprintf(stderr, "PIN code enumeration failed: %s\n", sc_strerror(r));
		return NULL;
	}
	if (opt_pin < 0 || opt_pin >= p15card->pin_count) {
		fprintf(stderr, "Selected PIN code not found.\n");
		return NULL;
	}
	pinfo = &p15card->pin_info[opt_pin];
	sprintf(buf, "Enter PIN [%s]: ", pinfo->com_attr.label);
	while (1) {
		pincode = getpass(buf);
		if (strlen(pincode) == 0)
			return NULL;
		if (strlen(pincode) < pinfo->min_length ||
		    strlen(pincode) > pinfo->stored_length)
		    	continue;
		return pincode;
	}
}

int list_pins()
{
	int r, i;

	r = sc_pkcs15_enum_pins(p15card);
	if (r < 0) {
		fprintf(stderr, "PIN code enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (!quiet)
		printf("Card has %d PIN code(s).\n\n", p15card->pin_count);
	for (i = 0; i < p15card->pin_count; i++) {
		struct sc_pkcs15_pin_info *pinfo = &p15card->pin_info[i];
		sc_pkcs15_print_pin_info(pinfo);
		printf("\n");
	}
	return 0;
}

int change_pin()
{
	const char *pincode = opt_pincode;
	
	if (pincode == NULL)
		pincode = get_pin();
	if (pincode == NULL)
		return 2;
	if (strlen(pincode) == 0) {
		fprintf(stderr, "No PIN code supplied.\n");
		return 2;
	}
	printf("Not working yet!\n");
	return 0;
}

int enum_dir(struct sc_path path, int depth)
{
	struct sc_file file;
	int r;
	u8 files[MAX_BUFFER_SIZE];
	u8 buf[2048];
	const char *tmps;

	r = sc_select_file(card, &file, &path, SC_SELECT_FILE_BY_PATH);
	if (r) {
		fprintf(stderr, "SELECT FILE failed: %s\n", sc_strerror(r));
		return 1;
	}
	for (r = 0; r < depth; r++) {
		printf("  ");
	}
	for (r = 0; r < path.len; r++) {
		printf("%02X", path.value[r]);
		if (r && (r & 1) == 1)
			printf(" ");
	}
	if (sc_file_valid(&file)) {
		if (file.namelen) {
			printf("[");
			sc_print_binary(file.name, file.namelen);
			printf("] ");
		}
		switch (file.type) {
		case 0:
			tmps = "wEF";
			break;
		case 1:
			tmps = "iEF";
			break;
		case 7:
			tmps = "DF";
			break;
		default:
			tmps = "unknown";
			break;
		}	
		printf("type: %-3s ", tmps);
		if (file.type != 7)
			printf("ef structure: %d ", file.ef_structure);
		printf("size: %d ", file.size);
		if (file.type == 0 && 0) {
			r = sc_read_binary(card, 0, buf, file.size);
			if (r > 0)
				sc_hex_dump(buf, r);
		}
		if (file.sec_attr_len) {
			printf("sec: ");
			/* Octets are as follows:
			 *   DF: select, lock, delete, create, rehab, inval
			 *   EF: read, update, write, erase, rehab, inval
			 * 4 MSB's of the octet mean:			 
			 *  0 = ALW, 1 = PIN1, 2 = PIN2, 4 = SYS,
			 * 15 = NEV */
			sc_hex_dump(file.sec_attr, file.sec_attr_len);
		} else {
			printf("\n");
		}
	} else {
		printf("\n");
	}
	if (!sc_file_valid(&file) || file.type == 7) {
		int i;

		r = sc_list_files(card, files, sizeof(files));
		if (r <= 0) {
			fprintf(stderr, "sc_list_files() failed: %s\n", sc_strerror(r));
			return 1;
		}
		for (i = 0; i < r/2; i++) {
			struct sc_path tmppath;

			memcpy(&tmppath, &path, sizeof(path));
			memcpy(tmppath.value + tmppath.len, files + 2*i, 2);
			tmppath.len += 2;
			enum_dir(tmppath, depth + 1);
		}
	}
	return 0;
}	

int list_files()
{
	struct sc_path path;
	int r;
	
	memcpy(path.value, "\x3F\x00", 2);
	path.len = 2;
	r = enum_dir(path, 0);
	return r;
}

int main(int argc, char * const argv[])
{
	int err = 0, r, c, long_optind = 0;
	int do_list_readers = 0;
	int do_read_cert = 0;
	int do_list_certs = 0;
	int do_list_pins = 0;
	int do_list_files = 0;
	int do_change_pin = 0;
	int action_count = 0;
		
	while (1) {
		c = getopt_long(argc, argv, "lfr:coqp:", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			continue;
		switch (c) {
		case 'r':
			opt_cert = optarg;
			do_read_cert = 1;
			action_count++;
			break;
		case 'l':
			do_list_readers = 1;
			action_count++;
			break;
		case 'f':
			do_list_files = 1;
			action_count++;
			break;
		case 'c':
			do_list_certs = 1;
			action_count++;
			break;
		case OPT_CHANGE_PIN:
			do_change_pin = 1;
			action_count++;
			break;
		case OPT_LIST_PINS:
			do_list_pins = 1;
			action_count++;
			break;
		case OPT_READER:
			opt_reader = atoi(optarg);
			break;
		case 'o':
			opt_outfile = optarg;
			break;
		case 'q':
			quiet++;
			break;
		case 'p':
			if (optarg == NULL && opt_pincode == NULL)
				opt_pincode = getpass("Enter PIN code: ");
			else if (optarg != NULL)
				opt_pincode = optarg;
			break;
		}
	}
	if (action_count == 0)
		print_usage_and_die();
	r = sc_establish_context(&ctx);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}
	if (do_list_readers) {
		if ((err = list_readers()))
			goto end;
		action_count--;
	}
	if (action_count <= 0)
		goto end;
	if (opt_reader >= ctx->reader_count || opt_reader < 0) {
		fprintf(stderr, "Illegal reader number. Only %d reader(s) configured.\n", ctx->reader_count);
		err = 1;
		goto end;
	}
	if (sc_detect_card(ctx, opt_reader) != 1) {
		fprintf(stderr, "Card not present.\n");
		return 3;
	}
	if (!quiet)
		fprintf(stderr, "Connecting to card in reader %s...\n", ctx->readers[opt_reader]);
	r = sc_connect_card(ctx, opt_reader, &card);
	if (r) {
		fprintf(stderr, "Failed to connect to card: %s\n", sc_strerror(r));
		err = 1;
		goto end;
	}

	sc_lock(card);
	
	if (do_list_files) {
		if ((err = list_files()))
			goto end;
		action_count--;
	}
	/* Here go the actions that do not require PKCS#15 */
	
	if (action_count <= 0)
		goto end;
	if (!quiet)
		fprintf(stderr, "Trying to find a PKCS#15 compatible card...\n");
	r = sc_pkcs15_init(card, &p15card);
	if (r) {
		fprintf(stderr, "PKCS#15 initialization failed: %s\n", sc_strerror(r));
		err = 1;
		goto end;
	}
	if (!quiet)
		fprintf(stderr, "Found %s!\n", p15card->label);
	if (do_list_certs) {
		if ((err = list_certificates()))
			goto end;
		action_count--;
	}
	if (do_read_cert) {
		if ((err = read_certificate()))
			goto end;
		action_count--;
	}
	if (do_list_pins) {
		if ((err = list_pins()))
			goto end;
		action_count--;
	}
	if (do_change_pin) {
		if ((err = change_pin()))
			goto end;
		action_count--;
	}
end:
	if (p15card)
		sc_pkcs15_destroy(p15card);
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_destroy_context(ctx);
	return err;
}
