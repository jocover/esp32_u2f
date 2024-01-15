// SPDX-License-Identifier: Apache-2.0
#define __STDC_WANT_LIB_EXT1__ 1 // C11's bounds-checking interface.
#include <string.h>

void memzero(void *pnt, size_t len) {
#ifdef __STDC_LIB_EXT1__
  memset_s(pnt, len, 0, len);
#else
  volatile unsigned char *p = pnt;
  while (len--)
    *p++ = 0;
#endif
}
