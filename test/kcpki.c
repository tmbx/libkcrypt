#include <string.h>
#include <kcpki.h>
#include  "test.h"

static void keypair_generation(kcpkey **pkey, kcskey **skey) {
    TASSERT(kcpki_new(pkey, skey, 42, 1024, KEY_TYPE_IDENTITY) == 0);
}

static void encryption(kcpkey *pkey, kcskey *skey) {
    const char *orig_data = "This is the original data to be encrypted.";

    kbuffer clear, encrypted, decrypted;
    kbuffer_init(&clear);
    kbuffer_init(&encrypted);
    kbuffer_init(&decrypted);

    kbuffer_write_cstr(&clear, orig_data);

    TASSERT(kcpkey_encrypt(pkey, &clear, &encrypted) == 0);
    TASSERT(kcskey_decrypt(skey, &encrypted, &decrypted) == 0);

    TASSERT(memcmp(decrypted.data, orig_data, strlen(orig_data)) == 0);

    kbuffer_clean(&clear);
    kbuffer_clean(&encrypted);
    kbuffer_clean(&decrypted);
}

static void signature(kcpkey *pkey, kcskey *skey) {
    const char *orig_data = "This is the original data to be signed.";

    kbuffer data, signature;
    kbuffer_init(&data);
    kbuffer_init(&signature);

    kbuffer_write_cstr(&data, orig_data);

    TASSERT(kcskey_sign(skey, GCRY_MD_SHA256, &data, &signature) == 0);
    TASSERT(kcpkey_verify(pkey, GCRY_MD_SHA256, &data, &signature) == 0);

    kbuffer_clean(&data);
    kbuffer_clean(&signature);
}

static void pkey_serialization(kcpkey *pkey, kcskey *skey) {
    const char *orig_data = "This is the original data to be signed.";

    kbuffer data, signature, serialized_pkey;
    kbuffer_init(&data);
    kbuffer_init(&signature);
    kbuffer_init(&serialized_pkey);
    kcpkey *pkey_2 = NULL;

    kbuffer_write_cstr(&data, orig_data);

    kcskey_sign(skey, GCRY_MD_SHA256, &data, &signature);

    TASSERT(kserializable_serialize((kserializable *)pkey, &serialized_pkey) == 0);

    TASSERT(kserializable_deserialize((kserializable **)&pkey_2, &serialized_pkey) == 0);

    TASSERT(kcpkey_verify(pkey_2, GCRY_MD_SHA256, &data, &signature) == 0);

    kbuffer_clean(&data);
    kbuffer_clean(&signature);
    kbuffer_clean(&serialized_pkey);
    kcpkey_destroy(pkey_2);
}

static void skey_serialization(kcpkey UNUSED(*pkey), kcskey UNUSED(*skey)) {
    const char *orig_data = "This is the original data to be encrypted.";

    kcskey *skey_2 = NULL;
    kbuffer clear, encrypted, decrypted, serialized_skey;
    kbuffer_init(&clear);
    kbuffer_init(&encrypted);
    kbuffer_init(&decrypted);
    kbuffer_init(&serialized_skey);

    kbuffer_write_cstr(&clear, orig_data);

    kcpkey_encrypt(pkey, &clear, &encrypted);

    TASSERT(kserializable_serialize((kserializable *)skey, &serialized_skey) == 0);

    TASSERT(kserializable_deserialize((kserializable **)&skey_2, &serialized_skey) == 0);

    TASSERT(kcskey_decrypt(skey_2, &encrypted, &decrypted) == 0);

    TASSERT(memcmp(decrypted.data, orig_data, strlen(orig_data)) == 0);

    kbuffer_clean(&clear);
    kbuffer_clean(&encrypted);
    kbuffer_clean(&decrypted);
    kbuffer_clean(&serialized_skey);
    kcskey_destroy(skey_2);
}


UNIT_TEST(pki) {
    kcpkey *pkey;
    kcskey *skey;

    keypair_generation(&pkey, &skey);
    encryption(pkey, skey);
    signature(pkey, skey);
    pkey_serialization(pkey, skey);
    skey_serialization(pkey, skey);
    
    kcpkey_destroy(pkey);
    kcskey_destroy(skey);
}
