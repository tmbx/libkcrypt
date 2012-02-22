/**
 * src/kcrypt.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * kcrypt main header file
 *
 * @author Kristian Benoit.
 */

#ifndef __K_CRYPT_H__
#define __K_CRYPT_H__

/**
 * Call these functions to initialize/finalize the library.
 * flags is build from these definitions that can be ored together.
 */
#define KC_QUICK_RANDOM (1 << 0)
#define KC_THREADED     (1 << 1)
#define KC_NO_SECMEM    (1 << 2)
void kcrypt_initialize(int flags);
void kcrypt_finalize();
int kcrypt_get_flags();

#endif /*__K_CRYPT_H__*/
