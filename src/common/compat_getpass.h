#ifndef __COMPAT_GETPASS_H
#define __COMPAT_GETPASS_H
#ifndef HAVE_GETPASS
char *getpass (const char *prompt);
#endif
#endif
