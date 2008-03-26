#ifndef RUTOKEN_H
#define RUTOKEN_H

int sc_rutoken_get_prkey_from_bin(const u8 *data, size_t len, struct sc_pkcs15_prkey **key);
int sc_rutoken_get_bin_from_prkey(const struct sc_pkcs15_prkey_rsa *rsa, u8 *key, size_t *keysize);

#endif
