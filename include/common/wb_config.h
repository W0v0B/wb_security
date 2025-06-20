#ifndef WB_CONFIG_H
#define WB_CONFIG_H

#include <stdlib.h>

#define WB_MALLOC(size)       malloc(size)
#define WB_FREE(ptr)          free(ptr)
#define WB_CALLOC(num, size)  calloc(num, size)

#endif // WB_CONFIG_H