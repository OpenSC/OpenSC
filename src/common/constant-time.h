/* Original source: https://github.com/openssl/openssl/blob/9890cc42daff5e2d0cad01ac4bf78c391f599a6e/include/internal/constant_time.h */

#ifndef CONSTANT_TIME_H
#define CONSTANT_TIME_H

#include <stdlib.h>
#include <string.h>

#if !defined(inline)
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define constant_inline inline
#elif defined(__GNUC__) && __GNUC__ >= 2
#elif defined(__GNUC__) && __GNUC__ >= 2
#elif defined(_MSC_VER)
#define constant_inline __inline
#else
#define constant_inline
#endif
#else			       /* use what caller wants as inline  may be from config.h */
#define constant_inline inline /* inline */
#endif

/*-
 * The boolean methods return a bitmask of all ones (0xff...f) for true
 * and 0 for false. For example,
 *      if (a < b) {
 *        c = a;
 *      } else {
 *        c = b;
 *      }
 * can be written as
 *      unsigned int lt = constant_time_lt(a, b);
 *      c = constant_time_select(lt, a, b);
 */

static constant_inline unsigned int
value_barrier(unsigned int a)
{
	volatile unsigned int r = a;
	return r;
}

static constant_inline size_t
value_barrier_s(size_t a)
{
	volatile size_t r = a;
	return r;
}

/* MSB */
static constant_inline size_t
constant_time_msb_s(size_t a)
{
	return 0 - (a >> (sizeof(a) * 8 - 1));
}

static constant_inline unsigned int
constant_time_msb(unsigned int a)
{
	return 0 - (a >> (sizeof(a) * 8 - 1));
}

/* Select */
static constant_inline unsigned int
constant_time_select(unsigned int mask, unsigned int a, unsigned int b)
{
	return (value_barrier(mask) & a) | (value_barrier(~mask) & b);
}

static constant_inline unsigned char
constant_time_select_8(unsigned char mask, unsigned char a, unsigned char b)
{
	return (unsigned char)constant_time_select(mask, a, b);
}

static constant_inline size_t
constant_time_select_s(size_t mask, size_t a, size_t b)
{
	return (value_barrier_s(mask) & a) | (value_barrier_s(~mask) & b);
}

/* Zero */
static constant_inline unsigned int
constant_time_is_zero(unsigned int a)
{
	return constant_time_msb(~a & (a - 1));
}

static constant_inline size_t
constant_time_is_zero_s(size_t a)
{
	return constant_time_msb_s(~a & (a - 1));
}

/* Comparison*/
static constant_inline size_t
constant_time_lt_s(size_t a, size_t b)
{
	return constant_time_msb_s(a ^ ((a ^ b) | ((a - b) ^ b)));
}

static constant_inline unsigned int
constant_time_lt(unsigned int a, unsigned int b)
{
	return constant_time_msb(a ^ ((a ^ b) | ((a - b) ^ b)));
}

static constant_inline unsigned int
constant_time_ge(unsigned int a, unsigned int b)
{
	return ~constant_time_lt(a, b);
}

/* Equality*/

static constant_inline unsigned int
constant_time_eq(unsigned int a, unsigned int b)
{
	return constant_time_is_zero(a ^ b);
}

static constant_inline size_t
constant_time_eq_s(size_t a, size_t b)
{
	return constant_time_is_zero_s(a ^ b);
}

static constant_inline unsigned int
constant_time_eq_i(int a, int b)
{
	return constant_time_eq((unsigned int)a, (unsigned int)b);
}

#endif /* CONSTANT_TIME_H */
