/**
 * libkcrypt/src/kcrypt.c
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt initialization
 *
 * @author Kristian Benoit
 */

#include <gcrypt.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <kmem.h>
#include "kcrypt.h"
#include <kserializable.h>
#include <ktools.h>

GCRY_THREAD_OPTION_PTHREAD_IMPL;

extern const struct kserializable_ops *kcrypt_serializable_array[];

static int not_secmem(const void *ptr) {
    ptr = ptr;
    return 0;
}

static int kcrypt_flags = 0;

int kcrypt_get_flags() {
    return kcrypt_flags;
}

/** Tagcrypt initialization.
 *
 * This function can be called many times without harm.
 */
void kcrypt_initialize(int flags) {
    int i;

    ktools_initialize();

    for (i = 0 ; kcrypt_serializable_array[i] != NULL ; i++) {
        kserializable_add_ops(kcrypt_serializable_array[i]);
    }

    gcry_set_allocation_handler(kmalloc,
                                kmalloc,
                                &not_secmem,
                                krealloc,
                                kfree);

    gcry_check_version (NULL);

    if (flags & KC_THREADED)
        gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    if (!(flags & KC_NO_SECMEM))
        gcry_control (GCRYCTL_INIT_SECMEM, 4096);
    if (flags & KC_QUICK_RANDOM)
        gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM); 

    kcrypt_flags = flags;
}

void kcrypt_finalize() {
    ktools_finalize();
}
