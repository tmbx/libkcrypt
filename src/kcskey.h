/**
 * tagcrypt/include/tagcryptskey.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt secret key management function.
 *
 * @author Kristian Benoit
 */

#ifndef __KC_SKEY_H__
#define __KC_SKEY_H__

#include <gcrypt.h>
#include <ktools.h>

/** An abstract secret key.
 * The secret key is used for decryption and signing.
 */
typedef struct kcskey {
    kserializable serializable;
    uint64_t keyid;
    gcry_sexp_t key;
} kcskey;

/** Free ressource used by a public key.
 * Use this function when a statically allocated public key
 * (tagcrypt_pkey_init) will not be used anymore.
 *
 * \param self the public key to clean.
 */
void kcskey_clean(kcskey *self);

/** Delete the secret key.
 * Use this function when a dynamically allocated secret key
 * (kcskey_new) will not be used anymore.
 *
 * \param self the secret key to destroy.
 */
void kcskey_destroy(kcskey     *self);

/** Decrypt data.
 * Decrypt in into out using self.
 *
 * \param self the secret key used to decrypt in (must match the public key used to encrypt).
 * \param in the data to decrypt.
 * \param out will contain the decrypted data after a successful call.
 * \return 0 on success, -1 on error.
 */
int kcskey_decrypt(kcskey *self, kbuffer *in, kbuffer *out);

/** Sign data.
 *
 * \param self the secret key used to sign data.
 * \param hash_algo the algo id to use for hashing data.
 * \param data the data to sign.
 * \param signature the returned signature.
 * \return 0 on success, -1 on error.
 */
int kcskey_sign(kcskey *self, uint32_t hash_algo, kbuffer *data, kbuffer *signature);

#endif /* __TAGCRYPTPKEY_H__ */

