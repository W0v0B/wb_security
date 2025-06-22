#ifndef WB_CONFIG_H
#define WB_CONFIG_H

#include <stdlib.h>
#include <string.h>

#ifndef WB_USER_CONFIG

#define WB_MALLOC(size)                                 malloc(size)
#define WB_FREE(ptr)                                    free(ptr)
#define WB_CALLOC(num, size)                            calloc(num, size)
#define WB_MEMCPY(dest, src, size)                      memcpy(dest, src, size)
#define WB_MEMCPY_S(dest, destsz, src, count)           memcpy_s(dest, destsz, src, count)
#define WB_MEMSET(ptr, value, size)                     memset(ptr, value, size)
#define WB_MEMSET_S(dest, destsz, src, count)           memset(ptr, value, size)

#endif // WB_USER_CONFIG

#define WB_CHECK_EMPTY_RETURN(ptr, err_code) \
    do { \
        if ((ptr) == NULL) { \
            return (err_code); \
        } \
    } while(0)

#endif // WB_CONFIG_H