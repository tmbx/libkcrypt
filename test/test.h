#ifndef __TEST_H__
#define __TEST_H__

#include <stdio.h>
#include <kerror.h>
#include <setjmp.h>

typedef void (*unit_test_t) ();

extern jmp_buf exception_buf;
extern int continue_on_error;
extern int jmp_value;
extern int verbose;
extern int nb_assert;
extern int nb_error;

#define TASSERT(_test_) ({ \
    nb_assert++; \
    kerror_reset(); \
    if (_test_) { \
        if (verbose) \
    	    fprintf(stderr, "  [0;32m*[0m %s:%u %s: [0;32mPASSED[0m (%s)\n", __FILE__, __LINE__, __FUNCTION__, #_test_); \
        kerror_reset(); \
    } else { \
        nb_error++; \
    	fprintf(stderr, "  [0;31m*[0m %s:%u %s: [0;31mFAILED[0m (%s)\n", __FILE__, __LINE__, __FUNCTION__, #_test_); \
        if (kerror_has_error()) { \
            kstr *errstr = kerror_str(); \
            fprintf(stderr, "      %s\n", errstr->data); \
            kstr_destroy(errstr); \
        } \
        if (!continue_on_error) \
            longjmp(exception_buf, jmp_value); \
    } \
})

#define UNIT_TEST(name) \
    void __test_##name()

#endif /*__TEST_H__*/
