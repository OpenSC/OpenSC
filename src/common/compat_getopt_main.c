/*
 * copy - test program for my getopt() re-implementation
 *
 * This program is in the public domain.
 */

#define COPYRIGHT \
"This program is in the public domain."

/* for isprint(), printf(), fopen(), perror(), getenv(), strcmp(), etc. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* for my getopt() re-implementation */
#include "compat_getopt.h"

#undef VERSION
#define VERSION "0.3"

/* the default verbosity level is 0 (no verbose reporting) */
static unsigned verbose = 0;

/* print version and copyright information */
static void
version(char *progname)
{
  printf("%s version %s\n"
         "%s\n",
         progname,
         VERSION,
         COPYRIGHT);
}

/* print a help summary */
static void
help(char *progname)
{
  printf("Usage: %s [options] [FILE]...\n"
         "Options:\n"
         "-h or -help             show this message and exit\n"
         "-append                 append to the output file\n"
         "-o FILE or\n"
         "-output FILE            send output to FILE (default is stdout)\n"
         "-r or --rotate          rotate letters 13 positions (rot13)\n"
         "-rNUM or\n"
         "--rotate=NUM            rotate letters NUM positions\n"
         "-truncate               truncate the output file "
                                 "(this is the default)\n"
         "-v or -verbose          increase the level of verbosity by 1"
                                 "(the default is 0)\n"
         "-vNUM or\n"
         "-verbose=NUM            set the level of verbosity to NUM\n"
         "-V or -version          print program version and exit\n"
         "\n"
         "This program reads the specified FILEs "
         "(or stdin if none are given)\n"
         "and writes their bytes to the specified output FILE "
         "(or stdout if none is\n"
         "given.) It can optionally rotate letters.\n",
         progname);
}

/* print usage information to stderr */
static void
usage(char *progname)
{
  fprintf(stderr,
          "Summary: %s [-help] [-version] [options] [FILE]...\n",
          progname);
}

/* input file handler -- returns nonzero or exit()s on failure */
static int
handle(char *progname,
       FILE *infile,  const char *infilename,
       FILE *outfile, const char *outfilename,
       int rotate)
{
  int c;
  unsigned long bytes_copied = 0;

  if (verbose > 2)
    {
      fprintf(stderr,
              "%s: copying from `%s' to `%s'\n",
              progname,
              infilename,
              outfilename);
    }
  while ((c = getc(infile)) != EOF)
    {
      if (rotate && isalpha(c))
        {
          const char *letters = "abcdefghijklmnopqrstuvwxyz";
          char *match;
          if ((match = strchr(letters, tolower(c))))
            {
              char rc = letters[(match - letters + rotate) % 26];
              if (isupper(c))
                rc = toupper(rc);
              c = rc;
            }
        }
      if (putc(c, outfile) == EOF)
        {
          perror(outfilename);
          exit(1);
        }
      bytes_copied ++;
    }
  if (! feof(infile))
    {
      perror(infilename);
      return 1;
    }
  if (verbose > 2)
    {
      fprintf(stderr,
              "%s: %lu bytes copied from `%s' to `%s'\n",
              progname, bytes_copied, infilename, outfilename);
    }
  return 0;
}

/* argument parser and dispatcher */
int
main(int argc, char * argv[])
{
  /* the program name */
  char *progname = argv[0];
  /* during argument parsing, opt contains the return value from getopt() */
  int opt;
  /* the output filename is initially 0 (a.k.a. stdout) */
  const char *outfilename = 0;
  /* the default return value is initially 0 (success) */
  int retval = 0;
  /* initially we truncate */
  int append = 0;
  /* initially we don't rotate letters */
  int rotate = 0;

  /* short options string */
  const char *shortopts = "Vho:r::v::";
  /* long options list */
  struct option longopts[] =
  {
    /* name,        has_arg,           flag, val */ /* longind */
    { "append",     no_argument,       0,     0  }, /*       0 */
    { "truncate",   no_argument,       0,     0  }, /*       1 */
    { "version",    no_argument,       0,    'V' }, /*       3 */
    { "help",       no_argument,       0,    'h' }, /*       4 */
    { "output",     required_argument, 0,    'o' }, /*       5 */
    { "rotate",     optional_argument, 0,    'r' }, /*       6 */
    { "verbose",    optional_argument, 0,    'v' }, /*       7 */
    /* end-of-list marker */
    { 0, 0, 0, 0 }
  };
  /* long option list index */
  int longind = 0;

  /*
   * print a warning when the POSIXLY_CORRECT environment variable will
   * interfere with argument placement
   */
  if (getenv("POSIXLY_CORRECT"))
    {
      fprintf(stderr,
              "%s: "
              "Warning: implicit argument reordering disallowed by "
              "POSIXLY_CORRECT\n",
              progname);
    }

  /* parse all options from the command line */
  while ((opt =
          getopt_long_only(argc, argv, shortopts, longopts, &longind)) != -1)
    switch (opt)
      {
      case 0: /* a long option without an equivalent short option */
        switch (longind)
          {
          case 0: /* -append */
            append = 1;
            break;
          case 1: /* -truncate */
            append = 0;
            break;
          default: /* something unexpected has happened */
            fprintf(stderr,
                    "%s: "
                    "getopt_long_only unexpectedly returned %d for `--%s'\n",
                    progname,
                    opt,
                    longopts[longind].name);
            return 1;
          }
        break;
      case 'V': /* -version */
        version(progname);
        return 0;
      case 'h': /* -help */
        help(progname);
        return 0;
      case 'r': /* -rotate[=NUM] */
        if (optarg)
          {
            /* we use this while trying to parse a numeric argument */
            char ignored;
            if (sscanf(optarg,
                       "%d%c",
                       &rotate,
                       &ignored) != 1)
              {
                fprintf(stderr,
                        "%s: "
                        "rotation `%s' is not a number\n",
                        progname,
                        optarg);
                usage(progname);
                return 2;
              }
            /* normalize rotation */
            while (rotate < 0)
              {
                rotate += 26;
              }
            rotate %= 26;
          }
        else
          rotate = 13;
        break;
      case 'o': /* -output=FILE */
        outfilename = optarg;
        /* we allow "-" as a synonym for stdout here */
        if (optarg && !strcmp(optarg, "-"))
          {
            outfilename = 0;
          }
        break;
      case 'v': /* -verbose[=NUM] */
        if (optarg)
          {
            /* we use this while trying to parse a numeric argument */
            char ignored;
            if (sscanf(optarg,
                       "%u%c",
                       &verbose,
                       &ignored) != 1)
              {
                fprintf(stderr,
                        "%s: "
                        "verbosity level `%s' is not a number\n",
                        progname,
                        optarg);
                usage(progname);
                return 2;
              }
          }
        else
          verbose ++;
        break;
      case '?': /* getopt_long_only noticed an error */
        usage(progname);
        return 2;
      default: /* something unexpected has happened */
        fprintf(stderr,
                "%s: "
                "getopt_long_only returned an unexpected value (%d)\n",
                progname,
                opt);
        return 1;
      }

  /* re-open stdout to outfilename, if requested */
  if (outfilename)
    {
      if (! freopen(outfilename, (append ? "a" : "w"), stdout))
        {
          perror(outfilename);
          return 1;
        }
    }
  else
    {
      /* make a human-readable version of the output filename "-" */
      outfilename = "stdout";
      /* you can't truncate stdout */
      append = 1;
    }

  if (verbose)
    {
      fprintf(stderr,
              "%s: verbosity level is %u; %s `%s'; rotation %d\n",
              progname,
              verbose,
              (append ? "appending to" : "truncating"),
              outfilename,
              rotate);
    }

  if (verbose > 1)
    {
      fprintf(stderr,
              "%s: %d input file(s) were given\n",
              progname,
              ((argc > optind) ? (argc - optind) : 0));
    }

  if (verbose > 3)
  {
      fprintf(stderr,
              "\topterr: %d\n\toptind: %d\n\toptopt: %d (%c)\n\toptarg: %s\n",
              opterr,
              optind,
              optopt, optopt,
              optarg ? optarg : "(null)");
  }

  /* handle each of the input files (or stdin, if no files were given) */
  if (optind < argc)
    {
      int argindex;

      for (argindex = optind; argindex < argc; argindex ++)
        {
          const char *infilename = argv[argindex];
          FILE *infile;

          /* we allow "-" as a synonym for stdin here */
          if (! strcmp(infilename, "-"))
            {
              infile = stdin;
              infilename = "stdin";
            }
          else if (! (infile = fopen(infilename, "r")))
            {
              perror(infilename);
              retval = 1;
              continue;
            }
          if (handle(progname,
                     infile, argv[optind],
                     stdout, outfilename,
                     rotate))
            {
              retval = 1;
              fclose(infile);
              continue;
            }
          if ((infile != stdin) && fclose(infile))
            {
              perror(infilename);
              retval = 1;
            }
        }
    }
  else
    {
      retval =
        handle(progname,
               stdin, "stdin",
               stdout, outfilename,
               rotate);
    }

  /* close stdout */
  if (fclose(stdout))
    {
      perror(outfilename);
      return 1;
    }

  if (verbose > 3)
    {
      fprintf(stderr,
              "%s: normal return, exit code is %d\n",
              progname,
              retval);
    }
  return retval;
}
