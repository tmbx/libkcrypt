/**
 * src/kcskey.c
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * secret key management function.
 *
 * @author Kristian Benoit
 */

#include <gcrypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <kserializable.h>
#include "kcpki.h"
#include "kcerror.h"
#include "kcsymkey.h"

#define TAGCRYPT_SKEY_MAJOR 1
#define TAGCRYPT_SKEY_MINOR 1

static int kcskey_serialize (kserializable *serializable, kbuffer *buffer) {
    kcskey *self = (kcskey *)serializable;
    size_t size = gcry_sexp_sprint (self->key, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    uint8_t *buf_ptr;

    kbuffer_write32(buffer, TAGCRYPT_SKEY_MAJOR);
    kbuffer_write32(buffer, TAGCRYPT_SKEY_MINOR);
    kbuffer_write64(buffer, (uint64_t) self->keyid);

    kbuffer_write32(buffer, (uint32_t) size);

    buf_ptr = kbuffer_write_nbytes(buffer, size);
    gcry_sexp_sprint (self->key,
                      GCRYSEXP_FMT_ADVANCED,
                      buf_ptr,
                      size);

    return 0;
}

static int kcskey_deserialize(kserializable *serializable, kbuffer *serialized_skey) {
    kcskey *self = (kcskey *)serializable;
    gcry_error_t gerr;
    int err = -1;
    uint32_t u32;
    uint32_t major;
    uint8_t *buf_ptr;

    do {
        if (kbuffer_read32(serialized_skey, &major)) {
            KCRYPT_ERROR_PUSH("could not read major");
            break;
        }
        if (kbuffer_read32(serialized_skey, &u32)) {
            KCRYPT_ERROR_PUSH("could not read minor");
            break;
        }
        if (kbuffer_read64(serialized_skey, &self->keyid)) {
            KCRYPT_ERROR_PUSH("could not read keyid");
            break;
        }
        if (kbuffer_read32(serialized_skey, &u32)) {
            KCRYPT_ERROR_PUSH("could not read key data length");
            break;
        }

        switch (major) {
            case 1:
                buf_ptr = kbuffer_read_nbytes(serialized_skey, u32);
                if (buf_ptr == NULL) {
                    KCRYPT_ERROR_PUSH("could not read key data");
                    break;
                }
                gerr = gcry_sexp_new (&self->key, buf_ptr, u32, 1);
                if (gerr) {
                    KCRYPT_ERROR_SET("could not instantiate the key (%s)", gcry_strerror(gerr));
                    break;
                }
                err = 0;
                break;
            default:
                KCRYPT_ERROR_SET("Invalid major number (%i)", major);
                break;
        }
        if (err)
            break;
        else
            err = -1;

        err = 0;
    } while (0);
    return err;
}

static kserializable *kcskey_alloc_serializable();

static void kcskey_destroy_serializable(kserializable *serializable) {
    kcskey_destroy((kcskey *)serializable);
}

static void kcskey_dump (kserializable *serializable, FILE *file) {
    serializable = serializable;
    file = file;
    //TODO
}

DECLARE_KSERIALIZABLE_OPS(kcskey) = {
    KSERIALIZABLE_TYPE_KCSKEY,
    kcskey_serialize,
    kcskey_deserialize,
    kcskey_alloc_serializable,
    kcskey_destroy_serializable,
    kcskey_dump,
};

void kcskey_init (kcpkey *self) {
    kserializable_init(&self->serializable, &KSERIALIZABLE_OPS(kcskey));
}

static kserializable *kcskey_alloc_serializable () {
    kserializable *self = (kserializable *)kmalloc(sizeof(kcskey));
    kserializable_init (self, &KSERIALIZABLE_OPS(kcskey));
    return self;
}

void kcskey_clean(kcskey *self) {
    if (self) 
        gcry_sexp_release(self->key);
}

void kcskey_destroy(kcskey *self) {
    kcskey_clean (self);
    kfree(self);
}

int kcskey_do_decrypt (kcskey *self, kbuffer *in, kbuffer *out) {
    size_t size;
    uint32_t len;
    uint8_t c;
    gcry_mpi_t mpi = NULL;
    gcry_sexp_t clear = NULL;
    gcry_sexp_t encrypted = NULL;
    gcry_error_t gerr;
    kbuffer *tmp_buf = kbuffer_new();
    uint8_t *buf_ptr;
    int err = -1;

    do  {
        gerr = gcry_mpi_scan(&mpi, GCRYMPI_FMT_SSH, in->data + in->pos, in->len - in->pos, &size);

        if (gerr) {
            KCRYPT_ERROR_SET("cannot get the mpi, libgcrypt says : %s", gcry_strerror(gerr));
            break;
        }

        in->pos += size;

        gerr = gcry_sexp_build (&encrypted, NULL, "(7:enc-val(5:flags)(3:rsa(1:a%m)))", mpi);

        if (gerr) {
            KCRYPT_ERROR_SET("cannot build sexp, libgcrypt says : %s", gcry_strerror(gerr));
            break;
        }

        gcry_mpi_release(mpi);

        gerr = gcry_pk_decrypt(&clear, encrypted, self->key);
        if (gerr) {
            KCRYPT_ERROR_SET("cannot decrypt, libgcrypt says : %s", gcry_strerror(gerr));
            break;
        }

        /* RSA SPECIFIC */
        mpi = gcry_sexp_nth_mpi (clear, 1, GCRYMPI_FMT_USG);
        if (!mpi) {
            KCRYPT_ERROR_SET("cannot parse decrypted value");
            break;
        }

        len = (gcry_mpi_get_nbits (mpi) + 7) / 8;
        buf_ptr = kbuffer_begin_write(tmp_buf, len);
        size = 0;
        gerr = gcry_mpi_print (GCRYMPI_FMT_STD, (unsigned char *)buf_ptr, (size_t)len, &size, mpi);
        kbuffer_end_write(tmp_buf, size);
        if (gerr) {
            KCRYPT_ERROR_SET("cannot copy decrypted data, libgcrypt says : %s", gcry_strerror (gerr));
            break;
        }

        if (kbuffer_read8(tmp_buf, &c)) {
            KCRYPT_ERROR_PUSH("cannot read magic number in decrypted data");
            break;
        }
        if (c == 0x02){
        } else if (c == 0xA4) {
            //TODO: check more bytes.
        } else {
            KCRYPT_ERROR_SET("Invalid magic number in decrypted data");
            break;
        }

        while (!kbuffer_eof(tmp_buf)) {
            if (kbuffer_read8(tmp_buf, &c))
                break;

            if (c == '\0') {
                err = 0;
                break;
            }
        }
        if (err)
            break;
        else
            err = -1;

        buf_ptr = kbuffer_write_nbytes(out, tmp_buf->len - tmp_buf->pos);
        kbuffer_read (tmp_buf, buf_ptr, tmp_buf->len - tmp_buf->pos);

        /* END RSA SPECIFIC */
        err = 0;
    } while (0);

    gcry_sexp_release (encrypted);
    gcry_sexp_release (clear);
    gcry_mpi_release (mpi);
    kbuffer_destroy (tmp_buf);
    return err;
}

static int kcskey_parse(kbuffer *in, kbuffer *enc_symkey, kbuffer *enc_data) {
    uint8_t *buf_ptr;
    uint32_t size;
    int err = -1;

    do {
        /* symmetric key */
        if (kbuffer_read32(in, &size)) {
            KCRYPT_ERROR_PUSH("could not read symmetric key size");
            break;
        }

        buf_ptr = kbuffer_write_nbytes(enc_symkey, size);
        if (kbuffer_read (in, buf_ptr, size)) {
            KCRYPT_ERROR_PUSH("could not read the symkey");
            break;
        }

        /* data */
        if (kbuffer_read32(in, &size)) {
            KCRYPT_ERROR_PUSH("could not read the encrypted data size");
            break;
        }

        buf_ptr = kbuffer_write_nbytes(enc_data, size);
        if (kbuffer_read(in, buf_ptr, size)) {
            KCRYPT_ERROR_PUSH ("could not read encrypted data");
            break;
        }
        err = 0;
    }while (0);

    return err;

}

int kcskey_decrypt (kcskey *self, kbuffer *in, kbuffer *out) {
    kbuffer *enc_symkey = kbuffer_new (32);
    kbuffer *serialized_symkey = kbuffer_new (32);
    kbuffer *enc_data = kbuffer_new (32);
    kcsymkey *symkey = NULL;
    int err;

    do {
        if (kcskey_parse (in, enc_symkey, enc_data)) {
            KCRYPT_ERROR_PUSH("cannot parse the encrypted buffer");
            break;
        }

        if (kcskey_do_decrypt (self, enc_symkey, serialized_symkey)) {
            KCRYPT_ERROR_PUSH("could not decrypt the symmetric key");
            break;
        }

        if (kserializable_deserialize((kserializable **)&symkey, serialized_symkey)) {
            KCRYPT_ERROR_PUSH("could not restore the symmetric key");
            break;
        }

        if (kcsymkey_decrypt (symkey, enc_data, out)) {
            KCRYPT_ERROR_PUSH("could not decrypt the data");
            break;
        }

        err = 0;
    } while (0);

    kbuffer_destroy (enc_symkey);
    kbuffer_destroy (serialized_symkey);
    kbuffer_destroy (enc_data);
    kcsymkey_destroy (symkey);
    
    return err;
}

static int kcpkey_sign_rsa(kcskey *self, gcry_sexp_t sig, kbuffer *buffer) {
    unsigned char  *signature   = NULL;
    gcry_sexp_t     tmp_sexp    = NULL;
    gcry_mpi_t      mpi         = NULL;
    size_t          nbytes;
    self = self;
    int err = -1;
    gcry_error_t gerr;

    do {
        tmp_sexp = gcry_sexp_find_token(sig, "s", 1);
        if (tmp_sexp == NULL) {
            KCRYPT_ERROR_SET("cannot find signature in gcrypt data");
            break;
        }

        mpi = gcry_sexp_nth_mpi(tmp_sexp, 1, GCRYMPI_FMT_USG);

        gerr = gcry_mpi_aprint(GCRYMPI_FMT_PGP, &signature, &nbytes, mpi);
        if (gerr) {
            KCRYPT_ERROR_SET("cannot copy signature data from gcrypt (%s)", gcry_strerror(gerr));
            break;
        }

        kbuffer_write32(buffer, (uint32_t)nbytes);

        kbuffer_write(buffer, (uint8_t *)signature, (uint32_t)nbytes);

        err = 0;
    } while (0);

    gcry_free (signature);
    gcry_mpi_release (mpi);
    gcry_sexp_release (tmp_sexp);
    return err;
}

#define MAX_HASH_NAME_LEN 32

int kcskey_sign(kcskey *self, uint32_t hash_algo, kbuffer *data, kbuffer *signature) {
    gcry_error_t gerr = 0;
    gcry_sexp_t hash_sexp = NULL;
    gcry_sexp_t sig = NULL;
    size_t hash_len = gcry_md_get_algo_dlen(hash_algo);
    uint8_t *digest;
    char hash_name[MAX_HASH_NAME_LEN];
    const char *algo_name = NULL;
    int err = -1;

    do {

        algo_name = gcry_md_algo_name(hash_algo);
        strncpy(hash_name, algo_name, MAX_HASH_NAME_LEN);
        strntolower(hash_name, MAX_HASH_NAME_LEN);

        digest = kmalloc(hash_len);

        gcry_md_hash_buffer(hash_algo, digest, data->data + data->pos, data->len - data->pos);
        gerr = gcry_sexp_build(&hash_sexp,
                              NULL,
                              "(4:data(5:flags5:pkcs1)(4:hash%s%b))",
                              hash_name,
                              hash_len,
                              digest);
        if (gerr) {
            KCRYPT_ERROR_SET("could not format data for signing by gcrypt (%s)", gcry_strerror(gerr));
            break;
        }

        gerr = gcry_pk_sign (&sig, hash_sexp, self->key);
        if (gerr) {
            KCRYPT_ERROR_SET("could not sign the data (%s)", gcry_strerror(gerr));
            break;
        }
        if (kcpkey_sign_rsa (self, sig, signature)) {
            KCRYPT_ERROR_PUSH("rsa signature parsing failed");
            break;
        }

        err = 0;
    } while (0);

    kfree(digest);
    gcry_sexp_release (hash_sexp);
    gcry_sexp_release (sig);

    return err;
}
