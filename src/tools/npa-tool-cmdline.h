/** @file npa-tool-cmdline.h
 *  @brief The header file for the command line option parser
 *  generated by GNU Gengetopt version 2.23
 *  http://www.gnu.org/software/gengetopt.
 *  DO NOT modify this file, since it can be overwritten
 *  @author GNU Gengetopt */

#ifndef NPA_TOOL_CMDLINE_H
#define NPA_TOOL_CMDLINE_H

/* If we use autoconf.  */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h> /* for FILE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef CMDLINE_PARSER_PACKAGE
/** @brief the program name (used for printing errors) */
#define CMDLINE_PARSER_PACKAGE "npa-tool"
#endif

#ifndef CMDLINE_PARSER_PACKAGE_NAME
/** @brief the complete program name (used for help and version) */
#define CMDLINE_PARSER_PACKAGE_NAME "npa-tool"
#endif

#ifndef CMDLINE_PARSER_VERSION
/** @brief the program version */
#define CMDLINE_PARSER_VERSION VERSION
#endif

enum enum_application { application__NULL = -1, application_arg_eID = 0, application_arg_eMRTD };

/** @brief Where the command line options are stored */
struct gengetopt_args_info
{
  const char *help_help; /**< @brief Print help and exit help description.  */
  const char *version_help; /**< @brief Print version and exit help description.  */
  char * reader_arg;	/**< @brief Number of the reader to use. By default, the first reader with a present card is used. If the argument is an ATR, the reader with a matching card will be chosen..  */
  char * reader_orig;	/**< @brief Number of the reader to use. By default, the first reader with a present card is used. If the argument is an ATR, the reader with a matching card will be chosen. original value given at command line.  */
  const char *reader_help; /**< @brief Number of the reader to use. By default, the first reader with a present card is used. If the argument is an ATR, the reader with a matching card will be chosen. help description.  */
  unsigned int verbose_min; /**< @brief Use (several times) to be more verbose's minimum occurreces */
  unsigned int verbose_max; /**< @brief Use (several times) to be more verbose's maximum occurreces */
  const char *verbose_help; /**< @brief Use (several times) to be more verbose help description.  */
  char * pin_arg;	/**< @brief Run PACE with (transport) eID-PIN.  */
  char * pin_orig;	/**< @brief Run PACE with (transport) eID-PIN original value given at command line.  */
  const char *pin_help; /**< @brief Run PACE with (transport) eID-PIN help description.  */
  char * puk_arg;	/**< @brief Run PACE with PUK.  */
  char * puk_orig;	/**< @brief Run PACE with PUK original value given at command line.  */
  const char *puk_help; /**< @brief Run PACE with PUK help description.  */
  char * can_arg;	/**< @brief Run PACE with CAN.  */
  char * can_orig;	/**< @brief Run PACE with CAN original value given at command line.  */
  const char *can_help; /**< @brief Run PACE with CAN help description.  */
  char * mrz_arg;	/**< @brief Run PACE with MRZ (insert MRZ without newlines).  */
  char * mrz_orig;	/**< @brief Run PACE with MRZ (insert MRZ without newlines) original value given at command line.  */
  const char *mrz_help; /**< @brief Run PACE with MRZ (insert MRZ without newlines) help description.  */
  int env_flag;	/**< @brief Whether to use environment variables PIN, PUK, CAN, MRZ and NEWPIN. You may want to clean your environment before enabling this. (default=off).  */
  const char *env_help; /**< @brief Whether to use environment variables PIN, PUK, CAN, MRZ and NEWPIN. You may want to clean your environment before enabling this. help description.  */
  char * new_pin_arg;	/**< @brief Install a new PIN.  */
  char * new_pin_orig;	/**< @brief Install a new PIN original value given at command line.  */
  const char *new_pin_help; /**< @brief Install a new PIN help description.  */
  int resume_flag;	/**< @brief Resume eID-PIN (uses CAN to activate last retry) (default=off).  */
  const char *resume_help; /**< @brief Resume eID-PIN (uses CAN to activate last retry) help description.  */
  int unblock_flag;	/**< @brief Unblock PIN (uses PUK to activate three more retries) (default=off).  */
  const char *unblock_help; /**< @brief Unblock PIN (uses PUK to activate three more retries) help description.  */
  char ** cv_certificate_arg;	/**< @brief Card Verifiable Certificate to create a certificate chain. Can be used multiple times (order is important)..  */
  char ** cv_certificate_orig;	/**< @brief Card Verifiable Certificate to create a certificate chain. Can be used multiple times (order is important). original value given at command line.  */
  unsigned int cv_certificate_min; /**< @brief Card Verifiable Certificate to create a certificate chain. Can be used multiple times (order is important).'s minimum occurreces */
  unsigned int cv_certificate_max; /**< @brief Card Verifiable Certificate to create a certificate chain. Can be used multiple times (order is important).'s maximum occurreces */
  const char *cv_certificate_help; /**< @brief Card Verifiable Certificate to create a certificate chain. Can be used multiple times (order is important). help description.  */
  char * cert_desc_arg;	/**< @brief Certificate description to show for Terminal Authentication.  */
  char * cert_desc_orig;	/**< @brief Certificate description to show for Terminal Authentication original value given at command line.  */
  const char *cert_desc_help; /**< @brief Certificate description to show for Terminal Authentication help description.  */
  char * chat_arg;	/**< @brief Card holder authorization template to use (default is terminal's CHAT). Use 7F4C0E060904007F000703010203530103 to trigger EAC on the CAT-C (Komfortleser)..  */
  char * chat_orig;	/**< @brief Card holder authorization template to use (default is terminal's CHAT). Use 7F4C0E060904007F000703010203530103 to trigger EAC on the CAT-C (Komfortleser). original value given at command line.  */
  const char *chat_help; /**< @brief Card holder authorization template to use (default is terminal's CHAT). Use 7F4C0E060904007F000703010203530103 to trigger EAC on the CAT-C (Komfortleser). help description.  */
  char * auxiliary_data_arg;	/**< @brief Terminal's auxiliary data (default is determined by verification of validity, age and community ID)..  */
  char * auxiliary_data_orig;	/**< @brief Terminal's auxiliary data (default is determined by verification of validity, age and community ID). original value given at command line.  */
  const char *auxiliary_data_help; /**< @brief Terminal's auxiliary data (default is determined by verification of validity, age and community ID). help description.  */
  char * private_key_arg;	/**< @brief Terminal's private key.  */
  char * private_key_orig;	/**< @brief Terminal's private key original value given at command line.  */
  const char *private_key_help; /**< @brief Terminal's private key help description.  */
  char * cvc_dir_arg;	/**< @brief Where to look for the CVCA's certificate (default='/home/fm/.local/etc/eac/cvc').  */
  char * cvc_dir_orig;	/**< @brief Where to look for the CVCA's certificate original value given at command line.  */
  const char *cvc_dir_help; /**< @brief Where to look for the CVCA's certificate help description.  */
  char * x509_dir_arg;	/**< @brief Where to look for the CSCA's certificate (default='/home/fm/.local/etc/eac/x509').  */
  char * x509_dir_orig;	/**< @brief Where to look for the CSCA's certificate original value given at command line.  */
  const char *x509_dir_help; /**< @brief Where to look for the CSCA's certificate help description.  */
  int disable_ta_checks_flag;	/**< @brief Disable checking the validity period of CV certificates (default=off).  */
  const char *disable_ta_checks_help; /**< @brief Disable checking the validity period of CV certificates help description.  */
  int disable_ca_checks_flag;	/**< @brief Disable passive authentication (default=off).  */
  const char *disable_ca_checks_help; /**< @brief Disable passive authentication help description.  */
  enum enum_application application_arg;	/**< @brief What card application to select (default='eID').  */
  char * application_orig;	/**< @brief What card application to select original value given at command line.  */
  const char *application_help; /**< @brief What card application to select help description.  */
  int read_all_dgs_flag;	/**< @brief Read all available data groups (default=off).  */
  const char *read_all_dgs_help; /**< @brief Read all available data groups help description.  */
  int read_dg1_flag;	/**< @brief Read data group 1 (default=off).  */
  const char *read_dg1_help; /**< @brief Read data group 1 help description.  */
  int read_dg2_flag;	/**< @brief Read data group 2 (default=off).  */
  const char *read_dg2_help; /**< @brief Read data group 2 help description.  */
  int read_dg3_flag;	/**< @brief Read data group 3 (default=off).  */
  const char *read_dg3_help; /**< @brief Read data group 3 help description.  */
  int read_dg4_flag;	/**< @brief Read data group 4 (default=off).  */
  const char *read_dg4_help; /**< @brief Read data group 4 help description.  */
  int read_dg5_flag;	/**< @brief Read data group 5 (default=off).  */
  const char *read_dg5_help; /**< @brief Read data group 5 help description.  */
  int read_dg6_flag;	/**< @brief Read data group 6 (default=off).  */
  const char *read_dg6_help; /**< @brief Read data group 6 help description.  */
  int read_dg7_flag;	/**< @brief Read data group 7 (default=off).  */
  const char *read_dg7_help; /**< @brief Read data group 7 help description.  */
  int read_dg8_flag;	/**< @brief Read data group 8 (default=off).  */
  const char *read_dg8_help; /**< @brief Read data group 8 help description.  */
  int read_dg9_flag;	/**< @brief Read data group 9 (default=off).  */
  const char *read_dg9_help; /**< @brief Read data group 9 help description.  */
  int read_dg10_flag;	/**< @brief Read data group 10 (default=off).  */
  const char *read_dg10_help; /**< @brief Read data group 10 help description.  */
  int read_dg11_flag;	/**< @brief Read data group 11 (default=off).  */
  const char *read_dg11_help; /**< @brief Read data group 11 help description.  */
  int read_dg12_flag;	/**< @brief Read data group 12 (default=off).  */
  const char *read_dg12_help; /**< @brief Read data group 12 help description.  */
  int read_dg13_flag;	/**< @brief Read data group 13 (default=off).  */
  const char *read_dg13_help; /**< @brief Read data group 13 help description.  */
  int read_dg14_flag;	/**< @brief Read data group 14 (default=off).  */
  const char *read_dg14_help; /**< @brief Read data group 14 help description.  */
  int read_dg15_flag;	/**< @brief Read data group 15 (default=off).  */
  const char *read_dg15_help; /**< @brief Read data group 15 help description.  */
  int read_dg16_flag;	/**< @brief Read data group 16 (default=off).  */
  const char *read_dg16_help; /**< @brief Read data group 16 help description.  */
  int read_dg17_flag;	/**< @brief Read data group 17 (default=off).  */
  const char *read_dg17_help; /**< @brief Read data group 17 help description.  */
  int read_dg18_flag;	/**< @brief Read data group 18 (default=off).  */
  const char *read_dg18_help; /**< @brief Read data group 18 help description.  */
  int read_dg19_flag;	/**< @brief Read data group 19 (default=off).  */
  const char *read_dg19_help; /**< @brief Read data group 19 help description.  */
  int read_dg20_flag;	/**< @brief Read data group 20 (default=off).  */
  const char *read_dg20_help; /**< @brief Read data group 20 help description.  */
  int read_dg21_flag;	/**< @brief Read data group 21 (default=off).  */
  const char *read_dg21_help; /**< @brief Read data group 21 help description.  */
  char * write_dg17_arg;	/**< @brief Write data group 17.  */
  char * write_dg17_orig;	/**< @brief Write data group 17 original value given at command line.  */
  const char *write_dg17_help; /**< @brief Write data group 17 help description.  */
  char * write_dg18_arg;	/**< @brief Write data group 18.  */
  char * write_dg18_orig;	/**< @brief Write data group 18 original value given at command line.  */
  const char *write_dg18_help; /**< @brief Write data group 18 help description.  */
  char * write_dg19_arg;	/**< @brief Write data group 19.  */
  char * write_dg19_orig;	/**< @brief Write data group 19 original value given at command line.  */
  const char *write_dg19_help; /**< @brief Write data group 19 help description.  */
  char * write_dg20_arg;	/**< @brief Write data group 20.  */
  char * write_dg20_orig;	/**< @brief Write data group 20 original value given at command line.  */
  const char *write_dg20_help; /**< @brief Write data group 20 help description.  */
  char * write_dg21_arg;	/**< @brief Write data group 21.  */
  char * write_dg21_orig;	/**< @brief Write data group 21 original value given at command line.  */
  const char *write_dg21_help; /**< @brief Write data group 21 help description.  */
  char * verify_validity_arg;	/**< @brief Verify chip's validity with a reference date.  */
  char * verify_validity_orig;	/**< @brief Verify chip's validity with a reference date original value given at command line.  */
  const char *verify_validity_help; /**< @brief Verify chip's validity with a reference date help description.  */
  char * older_than_arg;	/**< @brief Verify age with a reference date.  */
  char * older_than_orig;	/**< @brief Verify age with a reference date original value given at command line.  */
  const char *older_than_help; /**< @brief Verify age with a reference date help description.  */
  char * verify_community_arg;	/**< @brief Verify community ID with a reference ID.  */
  char * verify_community_orig;	/**< @brief Verify community ID with a reference ID original value given at command line.  */
  const char *verify_community_help; /**< @brief Verify community ID with a reference ID help description.  */
  int break_flag;	/**< @brief Brute force PIN, CAN or PUK. Use together with -p, -a or -u (default=off).  */
  const char *break_help; /**< @brief Brute force PIN, CAN or PUK. Use together with -p, -a or -u help description.  */
  char * translate_arg;	/**< @brief File with APDUs of HEX_STRINGs to send through the secure channel (default='stdin').  */
  char * translate_orig;	/**< @brief File with APDUs of HEX_STRINGs to send through the secure channel original value given at command line.  */
  const char *translate_help; /**< @brief File with APDUs of HEX_STRINGs to send through the secure channel help description.  */
  int tr_03110v201_flag;	/**< @brief Force compliance to BSI TR-03110 version 2.01 (default=off).  */
  const char *tr_03110v201_help; /**< @brief Force compliance to BSI TR-03110 version 2.01 help description.  */
  int disable_all_checks_flag;	/**< @brief Disable all checking of fly-by-data (default=off).  */
  const char *disable_all_checks_help; /**< @brief Disable all checking of fly-by-data help description.  */
  
  unsigned int help_given ;	/**< @brief Whether help was given.  */
  unsigned int version_given ;	/**< @brief Whether version was given.  */
  unsigned int reader_given ;	/**< @brief Whether reader was given.  */
  unsigned int verbose_given ;	/**< @brief Whether verbose was given.  */
  unsigned int pin_given ;	/**< @brief Whether pin was given.  */
  unsigned int puk_given ;	/**< @brief Whether puk was given.  */
  unsigned int can_given ;	/**< @brief Whether can was given.  */
  unsigned int mrz_given ;	/**< @brief Whether mrz was given.  */
  unsigned int env_given ;	/**< @brief Whether env was given.  */
  unsigned int new_pin_given ;	/**< @brief Whether new-pin was given.  */
  unsigned int resume_given ;	/**< @brief Whether resume was given.  */
  unsigned int unblock_given ;	/**< @brief Whether unblock was given.  */
  unsigned int cv_certificate_given ;	/**< @brief Whether cv-certificate was given.  */
  unsigned int cert_desc_given ;	/**< @brief Whether cert-desc was given.  */
  unsigned int chat_given ;	/**< @brief Whether chat was given.  */
  unsigned int auxiliary_data_given ;	/**< @brief Whether auxiliary-data was given.  */
  unsigned int private_key_given ;	/**< @brief Whether private-key was given.  */
  unsigned int cvc_dir_given ;	/**< @brief Whether cvc-dir was given.  */
  unsigned int x509_dir_given ;	/**< @brief Whether x509-dir was given.  */
  unsigned int disable_ta_checks_given ;	/**< @brief Whether disable-ta-checks was given.  */
  unsigned int disable_ca_checks_given ;	/**< @brief Whether disable-ca-checks was given.  */
  unsigned int application_given ;	/**< @brief Whether application was given.  */
  unsigned int read_all_dgs_given ;	/**< @brief Whether read-all-dgs was given.  */
  unsigned int read_dg1_given ;	/**< @brief Whether read-dg1 was given.  */
  unsigned int read_dg2_given ;	/**< @brief Whether read-dg2 was given.  */
  unsigned int read_dg3_given ;	/**< @brief Whether read-dg3 was given.  */
  unsigned int read_dg4_given ;	/**< @brief Whether read-dg4 was given.  */
  unsigned int read_dg5_given ;	/**< @brief Whether read-dg5 was given.  */
  unsigned int read_dg6_given ;	/**< @brief Whether read-dg6 was given.  */
  unsigned int read_dg7_given ;	/**< @brief Whether read-dg7 was given.  */
  unsigned int read_dg8_given ;	/**< @brief Whether read-dg8 was given.  */
  unsigned int read_dg9_given ;	/**< @brief Whether read-dg9 was given.  */
  unsigned int read_dg10_given ;	/**< @brief Whether read-dg10 was given.  */
  unsigned int read_dg11_given ;	/**< @brief Whether read-dg11 was given.  */
  unsigned int read_dg12_given ;	/**< @brief Whether read-dg12 was given.  */
  unsigned int read_dg13_given ;	/**< @brief Whether read-dg13 was given.  */
  unsigned int read_dg14_given ;	/**< @brief Whether read-dg14 was given.  */
  unsigned int read_dg15_given ;	/**< @brief Whether read-dg15 was given.  */
  unsigned int read_dg16_given ;	/**< @brief Whether read-dg16 was given.  */
  unsigned int read_dg17_given ;	/**< @brief Whether read-dg17 was given.  */
  unsigned int read_dg18_given ;	/**< @brief Whether read-dg18 was given.  */
  unsigned int read_dg19_given ;	/**< @brief Whether read-dg19 was given.  */
  unsigned int read_dg20_given ;	/**< @brief Whether read-dg20 was given.  */
  unsigned int read_dg21_given ;	/**< @brief Whether read-dg21 was given.  */
  unsigned int write_dg17_given ;	/**< @brief Whether write-dg17 was given.  */
  unsigned int write_dg18_given ;	/**< @brief Whether write-dg18 was given.  */
  unsigned int write_dg19_given ;	/**< @brief Whether write-dg19 was given.  */
  unsigned int write_dg20_given ;	/**< @brief Whether write-dg20 was given.  */
  unsigned int write_dg21_given ;	/**< @brief Whether write-dg21 was given.  */
  unsigned int verify_validity_given ;	/**< @brief Whether verify-validity was given.  */
  unsigned int older_than_given ;	/**< @brief Whether older-than was given.  */
  unsigned int verify_community_given ;	/**< @brief Whether verify-community was given.  */
  unsigned int break_given ;	/**< @brief Whether break was given.  */
  unsigned int translate_given ;	/**< @brief Whether translate was given.  */
  unsigned int tr_03110v201_given ;	/**< @brief Whether tr-03110v201 was given.  */
  unsigned int disable_all_checks_given ;	/**< @brief Whether disable-all-checks was given.  */

} ;

/** @brief The additional parameters to pass to parser functions */
struct cmdline_parser_params
{
  int override; /**< @brief whether to override possibly already present options (default 0) */
  int initialize; /**< @brief whether to initialize the option structure gengetopt_args_info (default 1) */
  int check_required; /**< @brief whether to check that all required options were provided (default 1) */
  int check_ambiguity; /**< @brief whether to check for options already specified in the option structure gengetopt_args_info (default 0) */
  int print_errors; /**< @brief whether getopt_long should print an error message for a bad option (default 1) */
} ;

/** @brief the purpose string of the program */
extern const char *gengetopt_args_info_purpose;
/** @brief the usage string of the program */
extern const char *gengetopt_args_info_usage;
/** @brief the description string of the program */
extern const char *gengetopt_args_info_description;
/** @brief all the lines making the help output */
extern const char *gengetopt_args_info_help[];

/**
 * The command line parser
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser (int argc, char **argv,
  struct gengetopt_args_info *args_info);

/**
 * The command line parser (version with additional parameters - deprecated)
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @param override whether to override possibly already present options
 * @param initialize whether to initialize the option structure my_args_info
 * @param check_required whether to check that all required options were provided
 * @return 0 if everything went fine, NON 0 if an error took place
 * @deprecated use cmdline_parser_ext() instead
 */
int cmdline_parser2 (int argc, char **argv,
  struct gengetopt_args_info *args_info,
  int override, int initialize, int check_required);

/**
 * The command line parser (version with additional parameters)
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @param params additional parameters for the parser
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_ext (int argc, char **argv,
  struct gengetopt_args_info *args_info,
  struct cmdline_parser_params *params);

/**
 * Save the contents of the option struct into an already open FILE stream.
 * @param outfile the stream where to dump options
 * @param args_info the option struct to dump
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_dump(FILE *outfile,
  struct gengetopt_args_info *args_info);

/**
 * Save the contents of the option struct into a (text) file.
 * This file can be read by the config file parser (if generated by gengetopt)
 * @param filename the file where to save
 * @param args_info the option struct to save
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_file_save(const char *filename,
  struct gengetopt_args_info *args_info);

/**
 * Print the help
 */
void cmdline_parser_print_help(void);
/**
 * Print the version
 */
void cmdline_parser_print_version(void);

/**
 * Initializes all the fields a cmdline_parser_params structure 
 * to their default values
 * @param params the structure to initialize
 */
void cmdline_parser_params_init(struct cmdline_parser_params *params);

/**
 * Allocates dynamically a cmdline_parser_params structure and initializes
 * all its fields to their default values
 * @return the created and initialized cmdline_parser_params structure
 */
struct cmdline_parser_params *cmdline_parser_params_create(void);

/**
 * Initializes the passed gengetopt_args_info structure's fields
 * (also set default values for options that have a default)
 * @param args_info the structure to initialize
 */
void cmdline_parser_init (struct gengetopt_args_info *args_info);
/**
 * Deallocates the string fields of the gengetopt_args_info structure
 * (but does not deallocate the structure itself)
 * @param args_info the structure to deallocate
 */
void cmdline_parser_free (struct gengetopt_args_info *args_info);

/**
 * Checks that all the required options were specified
 * @param args_info the structure to check
 * @param prog_name the name of the program that will be used to print
 *   possible errors
 * @return
 */
int cmdline_parser_required (struct gengetopt_args_info *args_info,
  const char *prog_name);

extern const char *cmdline_parser_application_values[];  /**< @brief Possible values for application. */


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* NPA_TOOL_CMDLINE_H */
