#ifndef INCLUDE_COMMON_WB_SECURE_UTILS_H
#define INCLUDE_COMMON_WB_SECURE_UTILS_H

#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef unsigned long rsize_t;
typedef int errno_t;

errno_t memset_s(void *dest, rsize_t destsz, int ch, rsize_t count);

errno_t memset_free_s(void *dest, rsize_t destsz, int ch, rsize_t count);

errno_t memcpy_s(void *dest, rsize_t destsz, const void *src, rsize_t count);

#endif // INCLUDE_COMMON_WB_SECURE_UTILS_H