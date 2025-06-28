#include "wb_secure_utils.h"

errno_t memset_s(void *dest, rsize_t destsz, int ch, rsize_t count)
{
    if (dest == NULL || destsz == 0) {
        errno = EINVAL;
        return EINVAL;
    }
    if (count > destsz) {
        memset(dest, 0, destsz);
        errno = ERANGE;
        return ERANGE;
    }

    memset(dest, ch, count);

    return 0;
}

errno_t memset_free_s(void *dest, rsize_t destsz, int ch, rsize_t count)
{
    if (dest == NULL || destsz == 0) {
        errno = EINVAL;
        return EINVAL;
    }
    if (count > destsz) {
        memset(dest, 0, destsz);
        errno = ERANGE;
        return ERANGE;
    }

    volatile unsigned char *vptr = (volatile unsigned char *)dest;
    for (rsize_t i = 0; i < count; i++) {
        vptr[i] = (unsigned char)ch;
    }

    return 0;
}

errno_t memcpy_s(void *dest, rsize_t destsz, const void *src, rsize_t count)
{
    if (dest == NULL || src == NULL || destsz == 0) {
        errno = EINVAL;
        return EINVAL;
    }
    if (count > destsz) {
        errno = ERANGE;
        memset(dest, 0, destsz);
        return ERANGE;
    }

    memcpy(dest, src, count);
    return 0;
}