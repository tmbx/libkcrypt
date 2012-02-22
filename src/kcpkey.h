/**
 * kcpkey.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * kcrypt public key management functions.
 *
 * @author Kristian Benoit
 */

#ifndef __KC_PKEY_H__
#define __KC_PKEY_H__

#include <gcrypt.h>
#include <ktools.h>

/** The different uses of a key
 */
enum key_type {
    KEY_TYPE_MASTER = 0,
    KEY_TYPE_TIMESTAMP = 1,
    KEY_TYPE_IDENTITY = 2,
    KEY_TYPE_ENCRYPTION = 3,
};

/** An abstract public key.
 * The public key is used for encryption and verifications.
 */
typedef struct kcpkey {
    kserializable serializable;
    uint64_t keyid;
    enum key_type type;
    gcry_sexp_t key;
} kcpkey;

#if 0
//Put that old stuff in tbxsosd's wrapper.
/** Serialize the public key.
 * Get a binary buffer containing a serialized version of a public key.
 * The buffer is binary not base64. This is the format in the DB.
 *
 * \param pkey the public key to serialize.
 * \param buffer will contain the serialized pkey after success.
 * \return 0 on success, -1 on error.
 */
int kcpkey_serialize_for_db(kcpkey *pkey, kbuffer *buffer);

/** Initialize a public key.
 * Initialize a public key from a serialized public key (binary).
 * Use this function when initializing a static struct. Use pkey_new
 * to allocate the object for you.
 *
 * \param self the public key object to initialize.
 * \param serialized_pkey the buffer containing the serialized key.
 * \return 0 on success, -1 on error
 */
int kcpkey_init_from_db(kcpkey *self, kbuffer *serialized_pkey, enum key_type type);

/** Allocate and initialize a public key.
 * Create a public key from a serialized public key (binary).
 *
 * \param serialized_pkey the serialize key
 * \see kcpkey_serialize ()
 * \return a newly allocated public key object or NULL on error.
 */
kcpkey *kcpkey_new(kbuffer *serialized_pkey, enum key_type type);

/** Allocate and initialize a public key.
 * Create a public key from a serialized public key (binary).
 *
 * \param serialized_pkey the serialize key
 * \see kcpkey_serialize ()
 * \return a newly allocated public key object or NULL on error.
 */
kcpkey *kcpkey_new(kbuffer *serialized_pkey);

/** initialize a public key.
 * Create a public key from a serialized public key (binary).
 *
 * \param self the public key to initialize.
 * \param serialized_pkey the serialize key
 * \return 0 or -1 on error.
 */
int kcpkey_init(kcpkey *self, kbuffer *serialized_pkey);
#endif

/** Free ressources used by a public key.
 * Use this function when a statically allocated public key
 * (kcpkey_init) will not be used anymore.
 *
 * \param self the public key to clean.
 */
void kcpkey_clean(kcpkey *self);

/** Delete the public key.
 * Use this function when a dynamically allocated public key
 * (kcpkey_new) will not be used anymore.
 *
 * \param self the public key to destroy.
 */
void kcpkey_destroy(kcpkey *self);

/** Encrypt data.
 * Encrypt in into out using self.
 *
 * \param self the public use to encrypt in.
 * \param in the data to encrypt.
 * \param out will contain the encrypted data after a successful call.
 * \return 0 on success, -1 on error.
 */
int kcpkey_encrypt(kcpkey *self, kbuffer *in, kbuffer *out);

/** Verify a signature.
 *
 * \param self the pkey used to validate the signature.
 * \param data the data to validate.
 * \param signature, the signature of the data (preceded by a 32 bits length).
 * \return 0 on success, -1 on error.
 */
int kcpkey_verify(kcpkey *self, uint32_t hash_algo,
                  kbuffer *data, kbuffer *signature);

#endif /* __KC_PKEY_H__ */

