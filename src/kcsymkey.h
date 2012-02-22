#ifndef __KC_SYMKEY_H__
#define __KC_SYMKEY_H__

#include <gcrypt.h>
#include <kserializable.h>
#include <kbuffer.h>

enum kcsymkey_cipher {
    KC_CIPHER_NONE,
    KC_CIPHER_RIJNDAEL,
    KC_CIPHER_LAST
};

enum kcsymkey_mode {
    KC_CIPHER_MODE_NONE,
    KC_CIPHER_MODE_CBC,
    KC_CIPHER_MODE_CFB,
    KC_CIPHER_MODE_LAST
};

#define KC_CIPHER_DEFAULT KC_CIPHER_RIJNDAEL
#define KC_CIPHER_MODE_DEFAULT KC_CIPHER_MODE_CBC

/** A symmetric key.
 * A symmetric key is used for encrypting/decrypting data.
 */
typedef struct kcsymkey {
    kserializable serializable;
    enum kcsymkey_cipher cipher; /** the cipher identifier */
    enum kcsymkey_mode mode;     /** the cipher mode to use */
    size_t key_len;              /** the length in byte of the key */
    size_t block_len;            /** the length in byte of a block cipher */
    char *key;                   /** the key */
    char *iv;                    /** the initialization vector */
    gcry_cipher_hd_t hd;         /** a handle to the implementation of the cipher */
} kcsymkey;

/** Initialize a symmetric key with new data.
 *
 * \param self the symmetric key returned.
 * \param cipher the cipher identifier to use.
 * \param mode the cipher mode to use.
 * \return 0 on success, -1 on error.
 */
int kcsymkey_init(kcsymkey *self, enum kcsymkey_cipher cipher, enum kcsymkey_mode mode);

/** Allocate and initialize a new symmetric key.
 *
 * \param cipher the cipher identifier to use.
 * \param mode the cipher mode to use.
 * \return the newly created symmetric key on success, NULL on error.
 */
kcsymkey *kcsymkey_new_full(enum kcsymkey_cipher cipher, enum kcsymkey_mode mode);

/** Allocate and initialize a new symmetric key.
 * Allocate and initialize a new symmetric key using the default cipher/mode.
 *
 * \return the newly created symmetric key on success, NULL on error.
 */
static inline
kcsymkey *kcsymkey_new() {
    return kcsymkey_new_full(KC_CIPHER_DEFAULT, KC_CIPHER_MODE_DEFAULT);
}

/** Release ressources used by a symkey.
 * Use for statically allocated symkey.
 *
 * \param self the symmetric key to release.
 */
void kcsymkey_clean(kcsymkey *self);

/** Deallocate all ressources used by a symmetric key.
 *
 * \param self the symmetric key to destroy.
 */
void kcsymkey_destroy(kcsymkey *self);

/** Encrypt data with a symmetric key.
 *
 * \param self the symmetric key used to encrypt.
 * \param in the data to encrypt.
 * \param out the encrypted data returned.
 * \return 0 on success, -1 on error.
 */
int kcsymkey_encrypt(kcsymkey *self, kbuffer *in, kbuffer *out);

/** Decrypt data with a symmetric key.
 *
 * \param self the symmetric key used to decrypt.
 * \param in the data to decrypt.
 * \param out the decrypted data returned.
 * \return 0 on success, -1 on error.
 */
int kcsymkey_decrypt(kcsymkey *self, kbuffer *in, kbuffer *out);

#endif /*__KC_SYMKEY_H__*/
