#include "kcpki.h"
#include "kcerror.h"


int kcpki_new(kcpkey **pkey, kcskey **skey, uint64_t keyid, unsigned int keylen, enum key_type type){
    int err;
    keylen = keylen ? keylen : 1024;

    *pkey = (kcpkey *)kmalloc(sizeof(kcpkey));
    *skey = (kcskey *)kmalloc(sizeof(kcskey));

    err = kcpki_init(*pkey, *skey, keyid, keylen, type);

    if (err) {
        kfree(*pkey);
        kfree(*pkey);
    }
    return err;
}

static inline int kcpki_gen_rsa (gcry_sexp_t *key_pair, int size)
{
    gcry_sexp_t param = NULL;
    gcry_error_t err = 0;

    do {
        err = gcry_sexp_build (&param, NULL, "(6:genkey(3:rsa(5:nbits%d)))", size);
        if (err) {
            KCRYPT_ERROR_SET("cannot build sexp for key generation, gcrypt said (%s)", gcry_strerror(err));
            break;
        }

        err = gcry_pk_genkey (key_pair, param);
        if (err) {
            KCRYPT_ERROR_SET("cannot generate key pair, gcrypt said (%s)", gcry_strerror(err));
            break;
        }

    } while (0);

    gcry_sexp_release(param);

    return err ? -1 : 0;
}

void kcpkey_init(kcpkey *self);
void kcskey_init(kcskey *self);

int kcpki_init(kcpkey *pkey, kcskey *skey, uint64_t keyid, unsigned int keylen, enum key_type type){
    gcry_sexp_t key_pair;
    int err = -1;

    do {
        if (kcpki_gen_rsa (&key_pair, keylen)) {
            KCRYPT_ERROR_PUSH("could not generate rsa key pair");
            break;
        }

        skey->keyid = keyid;
        skey->type = type;
        skey->key = gcry_sexp_find_token (key_pair, "private-key", 11);
        kcskey_init(skey);

        pkey->keyid = keyid;
        pkey->type = type;
        pkey->key = gcry_sexp_find_token (key_pair, "public-key", 10);
        kcpkey_init(pkey);

        err = 0;
    } while (0);

    gcry_sexp_release(key_pair);

    return err;
}
