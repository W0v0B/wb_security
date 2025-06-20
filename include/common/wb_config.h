#ifndef WB_CONFIG_H
#define WB_CONFIG_H

#include <stdlib.h>
#include <string.h>

#ifndef WB_USER_CONFIG

#define WB_MALLOC(size)                 malloc(size)
#define WB_FREE(ptr)                    free(ptr)
#define WB_CALLOC(num, size)            calloc(num, size)
#define WB_MEMCPY(dest, src, size)      memcpy(dest, src, size)

#endif // WB_USER_CONFIG

#define WB_CHECK_EMPTY_RETURN(ptr, err_code) \
    do { \
        if ((ptr) == NULL) { \
            return (err_code); \
        } \
    } while(0)

#endif // WB_CONFIG_H