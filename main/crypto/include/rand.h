/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __RAND_H__
#define __RAND_H__

#include <stdint.h>
#include <stdlib.h>

/**
 * Get random 32-bit number
 *
 * @return random number
 */
uint32_t random32(void);

/**
 * Randomize the content of buffer
 *
 * @param buf Buffer
 * @param len Length of buffer
 */
void random_buffer(uint8_t *buf, size_t len);

/**
 * Get a random number from uniform distribution of [0, n)
 *
 * @param n Random range
 * @return random number
 */
uint32_t random_uniform(uint32_t n);

/**
 * Shuffle bytes randomly
 *
 * @param str Data
 * @param len Length of data
 */
void random_permute(char *buf, size_t len);

int mbedtls_rnd(void *ctx, unsigned char *buf, size_t n);

#endif
