
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 *
 * Pseudo-random number generator test program
 */

#include "sc-test.h"
#include "sc.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

int main(int argc, char *argv[])
{
	int i, c;
	int freq[256];
	struct timeval tv1, tv2;
	u8 buf[8];

	i = sc_test_init(&argc, argv);
	if (i < 0)
		return 1;

	for (i = 0; i < 256; i++)
		freq[i] = 0;
	c = 0;
	while (1) {
		if (c == 0)
			gettimeofday(&tv1, NULL);
		if (sc_get_random(card, buf, 8) != 0) {
			printf("sc_get_random() failed.\n");
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
			printf("Time to generate 64 bits of randomness: %lld ms\n",
			       (foo - foo2)/100);
			printf("Frequencies:\n");
			for (i = 0; i < 256; i++) {
				printf("%02X: %5d ", i, freq[i]);
			}
			printf("\n");
			c = 0;
		}
	}
}
