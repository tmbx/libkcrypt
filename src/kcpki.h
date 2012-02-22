/**
 * kcpki.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * kcrypt public key interface.
 *
 * @author Kristian Benoit
 */

#ifndef __KC_PKI_H__
#define __KC_PKI_H__

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

/** An abstract key.
 * The public key is used for encryption and verifications.
 * The secret key is used for decryption and signing.
 */
struct kcpki_key {
    kserializable serializable;
    uint64_t keyid;
    enum key_type type;
    gcry_sexp_t key;
};
typedef struct kcpki_key kcpkey;
typedef struct kcpki_key kcskey;

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
 * \param hashed_data the data to validate (hashed).
 * \param signature, the signature of the data (preceded by a 32 bits length).
 * \return 0 on success, -1 on error.
 */
int kcpkey_verify(kcpkey *self, uint32_t hash_algo,
                  kbuffer *hashed_data, kbuffer *signature);

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

/** Generate a key pair.
 *
 * \param pkey the public key.
 * \param skey the secret key.
 * \param keyid the memberid associated with this key.
 * \param keylen the length of the key, 0 is an alias for 1024.
 * \return 0 if there is no error -1 otherwise.
 */
int kcpki_new(kcpkey **pkey, kcskey **skey, uint64_t keyid, unsigned int keylen, enum key_type type);

int kcpki_init(kcpkey *pkey, kcskey *skey, uint64_t keyid, unsigned int keylen, enum key_type type);

#endif /* __KC_PKI_H__ */
