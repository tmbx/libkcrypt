#include "test.h"
#include "kcsymkey.h"
#include "kerror.h"

static void initialization (kcsymkey *symkey) {
    TASSERT(kcsymkey_init(symkey, KC_CIPHER_DEFAULT, KC_CIPHER_MODE_DEFAULT) == 0);
}

static void encryption (kcsymkey *symkey) {
    const char *data = "This is the original string";
    kbuffer raw_data, encrypted_data;
    kbuffer_init(&raw_data);
    kbuffer_init(&encrypted_data);
    kbuffer_write_cstr(&raw_data, data);

    TASSERT(kcsymkey_encrypt(symkey, &raw_data, &encrypted_data) == 0);

    kbuffer_reset(&raw_data);

    TASSERT(kcsymkey_decrypt(symkey, &encrypted_data, &raw_data) == 0);

    TASSERT(memcmp(raw_data.data, data, raw_data.len) == 0);

    kbuffer_clean(&raw_data);
    kbuffer_clean(&encrypted_data);
}

static void serialization(kcsymkey *symkey){
    const char *data = "This is the original string";
    kcsymkey *symkey_2 = NULL;
    kbuffer raw_data, encrypted_data, serialized_symkey;
    kbuffer_init(&raw_data);
    kbuffer_init(&encrypted_data);
    kbuffer_init(&serialized_symkey);

    TASSERT(kserializable_serialize((kserializable *)symkey, &serialized_symkey) == 0);

    kcsymkey_encrypt(symkey, &raw_data, &encrypted_data);

    kbuffer_reset(&raw_data);

    TASSERT(kserializable_deserialize((kserializable **)&symkey_2, &serialized_symkey) == 0);

    kcsymkey_decrypt(symkey_2, &encrypted_data, &raw_data);

    TASSERT(memcmp(raw_data.data, data, raw_data.len) == 0);

    kbuffer_clean(&raw_data);
    kbuffer_clean(&encrypted_data);
    kbuffer_clean(&serialized_symkey);
    kcsymkey_destroy(symkey_2);
}

UNIT_TEST(symkey) {
    kcsymkey symkey;

    initialization(&symkey);
    encryption(&symkey);
    serialization(&symkey);

    kcsymkey_clean(&symkey);
}
