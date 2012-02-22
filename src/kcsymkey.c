#include <kmem.h>
#include "kcsymkey.h"
#include "kcrypt.h"
#include "kcerror.h"

#define KCSYMKEY_FORMAT_VERSION 1

static int kcsymkey_cipher_kid_to_gid(enum kcsymkey_cipher cipher) {
    int gcry_cipher;
    switch (cipher) {
        case KC_CIPHER_RIJNDAEL:
            gcry_cipher = GCRY_CIPHER_RIJNDAEL;
            break;

        default:
            gcry_cipher = GCRY_CIPHER_NONE;
    }
    return gcry_cipher;
}

static int kcsymkey_mode_kid_to_gid(enum kcsymkey_mode mode) {
    int gcry_mode;
    switch (mode) {
        case KC_CIPHER_MODE_CBC:
            gcry_mode = GCRY_CIPHER_MODE_CBC;
            break;
        case KC_CIPHER_MODE_CFB:
            gcry_mode = GCRY_CIPHER_MODE_CFB;
            break;
        default:
            gcry_mode = GCRY_CIPHER_NONE;
    }
    return gcry_mode;
}


int kcsymkey_serialize(kserializable *serializable, kbuffer *buffer) {
    kcsymkey *self = (kcsymkey *)serializable;

    kbuffer_write8(buffer, KCSYMKEY_FORMAT_VERSION);
    kbuffer_write8(buffer, (uint8_t) self->cipher);
    kbuffer_write8(buffer, (uint8_t) self->mode);
    kbuffer_write(buffer, (uint8_t *) self->key, (uint32_t)self->key_len);
    kbuffer_write(buffer, (uint8_t *) self->iv, (uint32_t)self->block_len);
    return 0;
}

static inline int kcsymkey_init_gcrypt(kcsymkey *self) {
    unsigned int flags = 0;
    gcry_error_t err = 0;
    int gcry_cipher;
    int gcry_mode;

    do {
        if (!(kcrypt_get_flags() & KC_NO_SECMEM))
            flags |= GCRY_CIPHER_SECURE;

        gcry_cipher = kcsymkey_cipher_kid_to_gid(self->cipher);
        gcry_mode = kcsymkey_mode_kid_to_gid(self->mode);

        switch (self->mode) {
            case KC_CIPHER_MODE_CBC:
                flags |= GCRY_CIPHER_CBC_CTS;
                break;
            case KC_CIPHER_MODE_CFB:
                break;
            default:
                KCRYPT_ERROR_SET("unknown cipher mode %i", self->mode);
                err = -1;
        }
        if (err) break;

        err = gcry_cipher_open(&self->hd, gcry_cipher, gcry_mode, flags);
        if (err) {
            KCRYPT_ERROR_SET("cannot open cipher (%s)", gcry_strerror(err));
            break;
        }

        err = gcry_cipher_setkey (self->hd, self->key, self->key_len);
        if (err) {
            KCRYPT_ERROR_SET("cannot open cipher (%s)", gcry_strerror(err));
            break;
        }

    } while (0);

    if (err)
        gcry_cipher_close(self->hd);

    return (err) ? -1 : 0;
}

static int kcsymkey_deserialize(kserializable *serializable, kbuffer *buffer) {
    kcsymkey *self = (kcsymkey *)serializable;
    uint8_t format_version, cipher, mode;
    gcry_error_t err = 0;

    kerror_reset();
    self->key = NULL;
    self->iv = NULL;

    do {
        if (kbuffer_read8(buffer, &format_version)) {
            KCRYPT_ERROR_SET("could not read symkey format version");
            break;
        }
        if (format_version != 1) {
            KCRYPT_ERROR_SET("unknown symmetric key format %lu", format_version);
            break;
        }

        if (kbuffer_read8(buffer, &cipher)) {
            KCRYPT_ERROR_SET("end of buffer reached before reading the cipher id");
            break;
        }
        if (kbuffer_read8(buffer, &mode)) {
            KCRYPT_ERROR_SET("end of buffer reached before reading the cipher mode");
            break;
        }

        self->cipher = (enum kcsymkey_cipher)cipher;
        self->mode = (enum kcsymkey_mode)mode;

        err = gcry_cipher_algo_info(kcsymkey_cipher_kid_to_gid(self->cipher), GCRYCTL_GET_KEYLEN, NULL, &self->key_len);
        if (err) {
            KCRYPT_ERROR_SET("cannot get cipher key length (%s)", gcry_strerror(err));
            break;
        }

        err = gcry_cipher_algo_info(kcsymkey_cipher_kid_to_gid(self->cipher), GCRYCTL_GET_BLKLEN, NULL, &self->block_len);
        if (err) {
            KCRYPT_ERROR_SET("cannot get cipher block length (%s)", gcry_strerror(err));
            break;
        }

        self->key = (char *)kmalloc(self->key_len);
        self->iv = (char *)kmalloc(self->block_len);

        if (kbuffer_read(buffer, (uint8_t *)self->key, self->key_len) != 0) {
            KCRYPT_ERROR_PUSH("cannot read symetric key");
            break;
        }

        if (kbuffer_read(buffer, (uint8_t *)self->iv, self->block_len) != 0) {
            KCRYPT_ERROR_PUSH("cannot read initialization vector");
            break;
        }

        if (kcsymkey_init_gcrypt(self))
            break;

    } while (0);

    if (err) {
        kfree(self->key);
        kfree(self->iv);
    }

    return (err) ? -1 : 0;
}

static kserializable *kcsymkey_allocate_serializable();

static void kcsymkey_destroy_serializable (kserializable *serializable) {
    kcsymkey *self = (kcsymkey *)serializable;

    if (self && self->cipher)
        kcsymkey_destroy(self);
    else
        kfree(self);
}

static void kcsymkey_dump(kserializable *serializable, FILE *file) {
    kcsymkey *self = (kcsymkey *)serializable;
    self = self;
    file = file;
    //TODO
}

DECLARE_KSERIALIZABLE_OPS(kcsymkey) = {
    KSERIALIZABLE_TYPE_KCSYMKEY,
    kcsymkey_serialize,
    kcsymkey_deserialize,
    kcsymkey_allocate_serializable,
    kcsymkey_destroy_serializable,
    kcsymkey_dump
};

kserializable *kcsymkey_allocate_serializable() {
    kcsymkey *self = (kcsymkey *)kcalloc (sizeof(kcsymkey));
    kserializable_init(&self->serializable, &KSERIALIZABLE_OPS(kcsymkey));
    return (kserializable *)self;
}

int kcsymkey_init(kcsymkey *self, enum kcsymkey_cipher cipher, enum kcsymkey_mode mode) {
    int gcry_cipher;
    int gcry_mode;
    int err = 0;

    /* TRY */
    do {
        kserializable_init(&self->serializable, &KSERIALIZABLE_OPS(kcsymkey));

        self->cipher = cipher;
        self->mode = mode;

        gcry_cipher = kcsymkey_cipher_kid_to_gid(cipher);
        gcry_mode = kcsymkey_mode_kid_to_gid(mode);

        err = gcry_cipher_algo_info (gcry_cipher, GCRYCTL_TEST_ALGO, NULL, NULL);
        if (err) {
            KCRYPT_ERROR_SET("test symmetric cipher error (%s)", gcry_strerror (err));
            break;
        }

        err = gcry_cipher_algo_info(gcry_cipher, GCRYCTL_GET_KEYLEN, NULL, &self->key_len);
        if (err) {
            KCRYPT_ERROR_SET("cannot get cipher key len (%s)", gcry_strerror(err));
            break;
        }

        err = gcry_cipher_algo_info(gcry_cipher, GCRYCTL_GET_BLKLEN, NULL, &self->block_len);
        if (err) {
            KCRYPT_ERROR_SET("cannot get cipher block len (%s)", gcry_strerror(err));
            break;
        }


        self->iv = (char *)kmalloc(self->block_len);
        self->key = (char *)kmalloc(self->key_len);

        gcry_randomize (self->key, self->key_len, GCRY_VERY_STRONG_RANDOM);
        gcry_randomize (self->iv, self->block_len, GCRY_VERY_STRONG_RANDOM);

        if (kcsymkey_init_gcrypt(self)) {
            break;
            err = -1;
        }
    } while (0);

    return  (err) ? -1 : 0;
}

kcsymkey *kcsymkey_new_full(enum kcsymkey_cipher cipher, enum kcsymkey_mode mode) {
    kcsymkey *self = kmalloc(sizeof(kcsymkey));
    if (kcsymkey_init(self, cipher, mode)) {
        kfree(self);
        self = NULL;
    }
    return self;
}

void kcsymkey_clean(kcsymkey *self) {
    kfree(self->key);
    kfree(self->iv);
    gcry_cipher_close(self->hd);
};

void kcsymkey_destroy(kcsymkey *self) {
    if (self)
        kcsymkey_clean(self);
    kfree(self);
}

static uint8_t *get_random_non_zero(size_t n) {
    uint8_t *data = (uint8_t *)gcry_random_bytes_secure(n, GCRY_STRONG_RANDOM);
    size_t i, z = 0;

    for (i = 0 ; i < n ; i++) {
        if (data[i] == '\0')
            data[i] = data[z++];
    }

    while (z) {
        uint8_t *more_data;
        size_t nb = z + z / 128 + 3;
        more_data = (uint8_t *) gcry_random_bytes_secure(nb, GCRY_STRONG_RANDOM); 
        for (i = 0 ; i < nb && z ; i++)
            if (more_data[i] != '\0')
                data[--z] = more_data[i];
        gcry_free(more_data);
    }
    return data;
}

#define TAGCRYPT_SYMKEY_ENCRYPT_MAGIC (0x23A6F9DDE35CF931ll)
int kcsymkey_encrypt(kcsymkey *self, kbuffer *in, kbuffer *out) {
    int err;
    kbuffer padded_in;
    uint8_t *out_data;
    int missing_len;

    kbuffer_init(&padded_in);
    do {
        err = gcry_cipher_reset(self->hd);
        if (err) {
            KCRYPT_ERROR_SET("cannot reset cipher (%s)", gcry_strerror(err));
            break;
        }

        err = gcry_cipher_setiv(self->hd, self->iv, self->block_len);
        if (err) {
            KCRYPT_ERROR_SET("cannot set input vector (%s)", gcry_strerror(err));
            break;
        }

        missing_len = self->block_len - ((in->len + 9) % self->block_len);

        kbuffer_write64(&padded_in, TAGCRYPT_SYMKEY_ENCRYPT_MAGIC);

        if (missing_len) {
            uint8_t *rdata = get_random_non_zero (missing_len);
            kbuffer_write (&padded_in, (uint8_t *)rdata, missing_len);
            gcry_free (rdata);
        }

        kbuffer_write8 (&padded_in, '\0');
        kbuffer_write_buffer (&padded_in, in);

        out_data = kbuffer_write_nbytes(out, padded_in.len);
        err = gcry_cipher_encrypt(self->hd, 
                                  (char *)out_data, 
                                  padded_in.len, 
                                  padded_in.data, 
                                  padded_in.len);
        if (err) {
            KCRYPT_ERROR_SET("could not encrypt (%s)", gcry_strerror(err));
            break;
        }

    } while (0);

    kbuffer_clean (&padded_in);
    return err ? -1 : 0;
}

int kcsymkey_decrypt(kcsymkey *self, kbuffer *in, kbuffer *out) {
    int err;
    kbuffer *tmp = kbuffer_new();
    uint64_t m;
    uint8_t c;
    size_t len;

    do {
        err = gcry_cipher_reset(self->hd);
        if (err) {
            KCRYPT_ERROR_SET("could not reset cipher, gcrypt (%s)", gcry_strerror(err));
            break;
        }

        err = gcry_cipher_setiv(self->hd, self->iv, self->block_len);  
        if (err) {
            KCRYPT_ERROR_SET("could not set iv in cipher, gcrypt (%s)", gcry_strerror(err));
            break;
        }

        err = gcry_cipher_decrypt(self->hd, 
                                  (char *)tmp->data + tmp->len, 
                                  in->len, 
                                  (char *)in->data, in->len);
        if (err) {
            KCRYPT_ERROR_SET("decryption failed, gcrypt (%s)", gcry_strerror(err));
            break;
        }

        tmp->len += in->len;
        if (kbuffer_read64(tmp, &m)) {
            KCRYPT_ERROR_PUSH("could not read magic decryption value");
            err = -1;
            break;
        }

        if (m != TAGCRYPT_SYMKEY_ENCRYPT_MAGIC) {
            KCRYPT_ERROR_SET("decryption failed, wrong data optained after decryption");
            break;
        }

        while (1) {
            if (kbuffer_read8(tmp, &c)) {
                KCRYPT_ERROR_PUSH("premature end of ecrypted data");
                break;
            }

            if (c == 0)
                break;
        }

        len = tmp->len - tmp->pos;
        if (kbuffer_read(tmp, kbuffer_write_nbytes(out, len), len) != 0) {
            KCRYPT_ERROR_SET("buffering error while decrypting");
            break;
        }
    } while (0);

    kbuffer_destroy(tmp);

    return err ? -1 : 0;
}
