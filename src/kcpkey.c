/**
 * kcpkey.c
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * kcrypt public key management functions.
 *
 * @author Kristian Benoit
 */

#include <gcrypt.h>
#include <kcerror.h>
#include <kcpkey.h>
#include <kcsymkey.h>
#include <kserializable.h>

enum PKEY_PRIVACY {
    PKEY_TYPE_PUB = (0 << 7),
    PKEY_TYPE_PRIV = (1 << 7)
};

enum PKEY_ALGO {
    PKEY_ALGO_RSA = 1,
    PKEY_ALGO_DSA = 2
};

int kcpkey_serialize(kserializable *serializable, kbuffer *buffer) {
    kcpkey *self = (kcpkey *)serializable;
    gcry_error_t err = 0;
    size_t n_size;
    size_t e_size;
    gcry_sexp_t n_sexp;
    gcry_sexp_t e_sexp;
    gcry_mpi_t n_mpi;
    gcry_mpi_t e_mpi;
    uint8_t *buf_ptr;

    do {
        n_sexp = gcry_sexp_find_token (self->key, "n", 1);
        e_sexp = gcry_sexp_find_token (self->key, "e", 1);

        n_mpi = gcry_sexp_nth_mpi (n_sexp, 1, GCRYMPI_FMT_USG);
        e_mpi = gcry_sexp_nth_mpi (e_sexp, 1, GCRYMPI_FMT_USG);

        if (!e_sexp || !n_sexp || !e_mpi || !n_mpi) {
            KCRYPT_ERROR_SET("cannot get the mpis");
            err = -1;
            break;
        }
        err = gcry_mpi_print(GCRYMPI_FMT_STD, NULL, 0, &n_size, n_mpi);
        if (err) {
            KCRYPT_ERROR_SET("cannot get n size, libgcrypt says %s", gcry_strerror (err));
            break;
        }
        err = gcry_mpi_print(GCRYMPI_FMT_STD, NULL, 0, &e_size, e_mpi);
        if (err) {
            KCRYPT_ERROR_SET("cannot get e size, libgcrypt says %s", gcry_strerror (err));
            break;
        }

        kbuffer_write8(buffer, PKEY_TYPE_PUB | PKEY_ALGO_RSA); //Hard coded as it's the only type we support for now.
        kbuffer_write64(buffer, self->keyid);
        kbuffer_write8(buffer, (uint8_t)self->type);

        kbuffer_write32(buffer, n_size);

        buf_ptr = kbuffer_write_nbytes(buffer, n_size);
        err = gcry_mpi_print(GCRYMPI_FMT_STD, (unsigned char *)buf_ptr, n_size, NULL, n_mpi);
        if (err) {
            KCRYPT_ERROR_SET("cannot write n, libgcrypt says %s",gcry_strerror (err));
            break;
        }

        kbuffer_write32(buffer, e_size);
        buf_ptr = kbuffer_write_nbytes(buffer, e_size);
        err = gcry_mpi_print(GCRYMPI_FMT_STD, (unsigned char *)buf_ptr, e_size, NULL, e_mpi);
        if (err) {
            KCRYPT_ERROR_SET("cannot write e, libgcrypt says %s",gcry_strerror (err));
            break;
        }

    } while (0);

    gcry_sexp_release(e_sexp);
    gcry_sexp_release(n_sexp);
    gcry_mpi_release(e_mpi);
    gcry_mpi_release(n_mpi);

    return err?-1:0;
}

int kcpkey_deserialize (kserializable *serializable, kbuffer *buffer) {
    kcpkey *self = (kcpkey *)serializable;
    gcry_error_t err = -1;
    uint8_t key_type;
    uint32_t field_len;
    size_t n_size;
    size_t e_size;
    gcry_mpi_t n_mpi = NULL;
    gcry_mpi_t e_mpi = NULL;
    uint8_t *buf_ptr;

    do {
        if (kbuffer_read8 (buffer, &key_type) || (key_type & (1 << 7)) != PKEY_TYPE_PUB) {
            KCRYPT_ERROR_PUSH("error reading public key type");
            break;
        }
        if ((key_type & 0x7F) != PKEY_ALGO_RSA) {
            KCRYPT_ERROR_SET("invalid public key algorithm (%hhi)", key_type);
            break;
        }
            
        if (kbuffer_read64 (buffer, &self->keyid)) {
            KCRYPT_ERROR_PUSH("cannot read the key id");
            break;
        }

        if (kbuffer_read8 (buffer, &key_type)) {
            KCRYPT_ERROR_PUSH("cannot read the the key type");
            break;
        }
        self->type = (enum key_type)key_type;

        // The rest is rsa specific. Move to another function if multiple algo are available.
        if (kbuffer_read32 (buffer, &field_len)) {
            KCRYPT_ERROR_PUSH("cannot read rsa parameter n length");
            break;
        }
        n_size = field_len;
        buf_ptr = kbuffer_read_nbytes(buffer, n_size);
        if (buf_ptr == NULL) {
            KCRYPT_ERROR_PUSH("cannot read rsa parameter n");
            break;
        }
        err = gcry_mpi_scan (&n_mpi, GCRYMPI_FMT_STD, buf_ptr, n_size, NULL);
        if (err) {
            KCRYPT_ERROR_SET("cant scan parameter n mpi (%s)", gcry_strerror(err));
            break;
        }
        err = -1;

        if (kbuffer_read32 (buffer, &field_len)) {
            KCRYPT_ERROR_PUSH("cannot read rsa parameter e length");
            break;
        }
        e_size = field_len;
        buf_ptr = kbuffer_read_nbytes(buffer, e_size);
        if (buf_ptr == NULL) {
            KCRYPT_ERROR_PUSH("cannot read rsa parameter e");
            break;
        }
        err = gcry_mpi_scan (&e_mpi, GCRYMPI_FMT_STD, buf_ptr, e_size, NULL);
        if (err) {
            KCRYPT_ERROR_SET("cant scan parameter n mpi (%s)", gcry_strerror(err));
            break;
        }
        err = -1;

        err = gcry_sexp_build (&self->key, NULL, "(10:public-key(3:rsa(1:n%m)(1:e%m)))", n_mpi, e_mpi);
        if (err) {
            KCRYPT_ERROR_SET("build public key (%s)", gcry_strerror(err));
            break;
        }
        err = -1;

        err = 0;
    } while (0);

    gcry_mpi_release (n_mpi);
    gcry_mpi_release (e_mpi);
    return err ? -1 : 0;
}

kserializable *kcpkey_allocate_serializable();

void kcpkey_destroy_serializable(kserializable *serializable) {
    kcpkey_destroy((kcpkey *)serializable);
}

void kcpkey_dump(kserializable *serializable, FILE *file) {
    serializable = serializable;
    file = file;
    //TODO
}

DECLARE_KSERIALIZABLE_OPS(kcpkey) = {
    KSERIALIZABLE_TYPE_KCPKEY,
    kcpkey_serialize,
    kcpkey_deserialize,
    kcpkey_allocate_serializable,
    kcpkey_destroy_serializable,
    kcpkey_dump,
};

void kcpkey_init (kcpkey *self) {
    kserializable_init(&self->serializable, &KSERIALIZABLE_OPS(kcpkey));
}

kserializable *kcpkey_allocate_serializable() {
    kcpkey *self = (kcpkey *)kmalloc(sizeof(kcpkey));
    kcpkey_init(self);
    return (kserializable *)self;
}


void kcpkey_clean (kcpkey *self) {
    gcry_sexp_release(self->key);
}

void kcpkey_destroy (kcpkey *self) {
    if (self) 
        kcpkey_clean(self);

    kfree(self);
}

// PKCS#1 padding. (Only for version 2.1 of the PKCS#1)
#if 0
#define PKCS1_HASH SHA1
static int mask_generation_function (uint8_t *seed, uint32_t seed_len, 
                                     uint8_t *ret_mask, uint32_t mask_len) {
    uint32_t counter;
    uint32_t C;
    uint32_t mask_size = 0;
    unsigned char *tmp_T;
    gcry_error_t err;
    gcry_md_hd_t hash = NULL;

    err = gcry_md_open(&hash, PKCS1_HASH, 0); 
    if (err) 
        goto ERR;

    while (counter = 0 ; counter < mask_len / gcry_md_get_algo_dlen(GCRY_MD_SHA1) - 1 ; counter++)     {
        gcry_md_write(hash, seed, seed_len);

        C = htonl(counter);
        gcry_md_write(hash, &C, 4);
        
        tmp_T = gcry_md_read(hash, 0);
        memcpy(ret_mask + mask_size, tmp_T, 
               MIN(gcry_md_get_algo_dlen(GCRY_MD_SHA1), mask_len - mask_size));

        ret_mask += MIN(gcry_md_get_algo_dlen(GCRY_MD_SHA1), mask_len - mask_size);
        mask_size += MIN(gcry_md_get_algo_dlen(GCRY_MD_SHA1), mask_len - mask_size);
        gcry_md_reset(hash);
    }

    return 0;

ERR:
    if (hash) 
        gcry_md_close(hash);

    return -1;
}
#endif

int kcpkey_do_encrypt(kcpkey *self, kbuffer *in, kbuffer *out) {
    size_t size;
    uint32_t len;
    gcry_sexp_t clear = NULL;
    gcry_sexp_t encrypted = NULL;
    gcry_sexp_t tmp = NULL;
    gcry_mpi_t mpi = NULL;
    gcry_error_t gerr = 0;
    int err = -1;
    uint8_t *buf_ptr;

    do {
        gerr = gcry_sexp_build(&clear, NULL, "(4:data(5:flags5:pkcs1)(5:value%b))", in->len, in->data);
        if (gerr) {
            KCRYPT_ERROR_SET("cannot format data for encrypting in gcrypt (%s)", gcry_strerror(gerr));
            break;
        }

        gerr = gcry_pk_encrypt(&encrypted, clear, self->key);
        if (gerr) {
            KCRYPT_ERROR_SET("cannot encrypt (%s)", gcry_strerror(gerr));
            break;
        }

        /* RSA SPECIFIC */
        tmp = gcry_sexp_find_token(encrypted, "a", 1);
        if (!tmp) {
            KCRYPT_ERROR_SET("could not find encrypted data returned by gcrypt");
            break;
        }

        mpi = gcry_sexp_nth_mpi(tmp, 1, GCRYMPI_FMT_STD);
        if (!mpi) {
            KCRYPT_ERROR_SET("could not parse mpi");
            break;
        }

        len = (gcry_mpi_get_nbits(mpi) + 7) / 8 + 100;

        buf_ptr = kbuffer_begin_write(out, len);
        gerr = gcry_mpi_print(GCRYMPI_FMT_SSH, buf_ptr, 
                             (size_t)len, &size, mpi);
        if (gerr) {
            KCRYPT_ERROR_SET ("could not copy encrypted value (%s)", gcry_strerror (gerr));
            break;
        }
        kbuffer_end_write(out, size);

        /* END RSA SPECIFIC */
        err = 0;
    } while (0);

    gcry_sexp_release (tmp);
    gcry_sexp_release (encrypted);
    gcry_sexp_release (clear);
    gcry_mpi_release (mpi);

    return err ? -1 : 0;
}

int kcpkey_encrypt (kcpkey *self, kbuffer *in, kbuffer *out)
{
    kcsymkey *symkey = kcsymkey_new ();
    kbuffer *enc_data = kbuffer_new();
    kbuffer *serialized_symkey = kbuffer_new();
    kbuffer *enc_symkey = kbuffer_new();
    int err = -1;

    do {
        if (kcsymkey_encrypt(symkey, in, enc_data))  {
            KCRYPT_ERROR_PUSH("data encryption failed");
            break;
        }

        if (kserializable_serialize((kserializable *)symkey, serialized_symkey))  {
            KCRYPT_ERROR_PUSH("could not serialize the symmetric key");
            break;
        }

        if (kcpkey_do_encrypt(self, serialized_symkey, enc_symkey))  {
            KCRYPT_ERROR_PUSH("symmetric key encryption failed");
            break;
        }

        kbuffer_write32(out, enc_symkey->len);
        kbuffer_write(out, enc_symkey->data, enc_symkey->len);
        kbuffer_write32(out, enc_data->len);
        kbuffer_write(out, enc_data->data, enc_data->len);

        err = 0;
    } while (0);

    kbuffer_destroy(enc_data);
    kbuffer_destroy(serialized_symkey);
    kbuffer_destroy(enc_symkey);
    kcsymkey_destroy(symkey);
    return err ? -1 : 0;
}

//#define MAX_SIG_ALGO_NAME_LEN 32
#define MAX_HASH_ALGO_NAME_LEN 32

static int kcpkey_verify_rsa(kcpkey *self, kbuffer *buffer, gcry_sexp_t hash) {
    int err = -1;
    uint32_t len;
    size_t nscanned;
    gcry_mpi_t sig_mpi = NULL;
    gcry_sexp_t sig_sexp = NULL;

    do {
        if (kbuffer_read32(buffer, &len)) {
            KCRYPT_ERROR_PUSH("cannot read signature length");
            break;
        }

        if (buffer->len - buffer->pos < len) {
            KCRYPT_ERROR_SET("signature is too short for the length read"); 
            break;
        }

        gcry_mpi_scan(&sig_mpi, GCRYMPI_FMT_PGP, buffer->data + buffer->pos, (size_t)len, &nscanned);
        gcry_sexp_build(&sig_sexp, NULL, "(7:sig-val(3:rsa(1:s%m)))", sig_mpi);

        err = gcry_pk_verify(sig_sexp, hash, self->key);
        if (err) {
            KCRYPT_ERROR_SET("signature verification failed (%s)", gcry_strerror(err)); 
            break;
        }
        err = 0;
    } while (0);

    gcry_sexp_release(sig_sexp);
    gcry_mpi_release(sig_mpi);

    return err ? -1 : 0;
}

int kcpkey_verify(kcpkey *self, uint32_t hash_algo, kbuffer *data, kbuffer *signature) {
    int err = 0;
    gcry_sexp_t hash_sexp;
    int digest_len = gcry_md_get_algo_dlen (hash_algo);
    char hashname[MAX_HASH_ALGO_NAME_LEN];

    uint8_t *digest = (uint8_t *)kmalloc(digest_len); 

    do {
        strncpy(hashname, gcry_md_algo_name(hash_algo), MAX_HASH_ALGO_NAME_LEN);
        strntolower(hashname, MAX_HASH_ALGO_NAME_LEN);
        gcry_md_hash_buffer(hash_algo, digest, data->data + data->pos, data->len - data->pos);

        err = gcry_sexp_build(&hash_sexp, NULL, "(4:data(5:flags5:pkcs1)(4:hash%s%b))", 
                              hashname, digest_len, digest);
        if (err) {
            KCRYPT_ERROR_SET("cannot build verification sexp (%s)", gcry_strerror(err));
            break;
        }

        if (kcpkey_verify_rsa(self, signature, hash_sexp)) {
            err = -1;
            break;
        }
    } while (0);

    kfree(digest);
    gcry_sexp_release(hash_sexp);

    return err ? -1 : 0;
}

