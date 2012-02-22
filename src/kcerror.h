#ifndef __KC_ERROR_H__
#define __KC_ERROR_H__

#include <kerror.h>

# define KCRYPT_ERROR_PUSH(...) \
    KERROR_PUSH(1, 0, __VA_ARGS__)
# define KCRYPT_ERROR_SET(...) \
    KERROR_SET(1, 0, __VA_ARGS__)

#endif /*__KC_ERROR_H__*/
