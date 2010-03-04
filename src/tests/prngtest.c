/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 *
 * Pseudo-random number generator test program
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "libopensc/opensc.h"
#include "sc-test.h"

int main(int argc, char *argv[])
{
	struct timeval tv1, tv2;
	int i, c, cnt = 3, freq[256];
	u8 buf[8];

	i = sc_test_init(&argc, argv);
	if (i < 0)
		return 1;
	for (i = 0; i < 256; i++)
		freq[i] = 0;
	c = 0;
	while (cnt) {
		if ((c % 10) == 1) {
			printf(".");
			fflush(stdout);
		}
		if (c == 0)
			gettimeofday(&tv1, NULL);
		i = sc_get_challenge(card, buf, 8);
		if (i != 0) {
			fprintf(stderr, "sc_get_challenge() failed: %s\n", sc_strerror(i));
			sc_test_cleanup();
			return 1;
		}
		for (i = 0; i < 8; i++)
			freq[buf[i]]++;
		c++;
		if (c == 100) {
			unsigned long long foo, foo2;
			gettimeofday(&tv2, NULL);
			foo = tv2.tv_sec * 1000 + tv2.tv_usec / 1000;
			foo2 = tv1.tv_sec * 1000 + tv1.tv_usec / 1000;
			printf("\nTime to generate 64 bits of randomness: %lld ms\n",
			       (foo - foo2) / 100);
			printf("Frequencies:\n");
			for (i = 0; i < 256; i++) {
				if (i && (i & 0x07) == 0)
					printf("\n");
				printf("%02X: %3d ", i, freq[i]);
			}
			printf("\n");
			c = 0;
			cnt--;
		}
	}
	sc_test_cleanup();
	return 0;
}
