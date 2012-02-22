#ifndef __windows__
# define _GNU_SOURCE
#endif /*__windows__*/

#include <ktools.h>
#include <kerror.h>
#include <stdio.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <stdlib.h>
#include <signal.h>
#include <kcrypt.h>
#include <getopt.h>
#include "test.h"

/* A null terminated array of unit test functions */
extern const unit_test_t unit_test_array[];
jmp_buf exception_buf;
int jmp_value = 2;
int continue_on_error = 0;
int verbose = 0;
int nb_assert = 0;
int nb_error = 0;


void start_unit_test(unit_test_t func) {
#ifdef _GNU_SOURCE
    int retval;
    Dl_info info;
    dlerror();
    retval = dladdr(func, &info);
    if (verbose)
    {
        if (retval == 0) {
            printf ("0x%X:\n", (unsigned int)func);
        } else
            printf("%s:\n", info.dli_sname);
    }
#else
    printf ("0x%X:\n", (unsigned int)func);
#endif
    func();
}

void signal_handler(int sig) {
    void *array[20];
    int i, size = 20;
    char **strings;
    static int currently_handling = 0;

    /* Handle recursive segfault */
    if (currently_handling)
        exit(1);

    currently_handling = 1;

    fprintf(stderr, "  [0;31m***[0m Received signal #%d\n", sig);

    size = backtrace(array, size);
    strings = backtrace_symbols (array, size);

    for (i = 0; i < size; i++)
        printf ("    %s\n", strings[i]);

    free (strings);

    exit(-1);
}

int main (int UNUSED(argc), char UNUSED(**argv)) {
    const unit_test_t *func;
    int quiet = 0;

    while (1) {
        int c;
        int option_index = 0;
        static struct option long_options[] = {
            {"continue", 0, 0, 'c'},
            {"ignore", 0, 0, 'i'},
            {"verbose", 0, 0, 'v'},
            {"quiet", 0, 0, 'v'},
            {"help", 0, 0, 'h'},
            {0, 0, 0, 0}
        };

        c = getopt_long (argc, argv, "civqh",
                         long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'c':
                jmp_value = 1;
                break;
            case 'i':
                continue_on_error = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'q':
                quiet = 1;
                break;
            case 'h':
            default:
                fprintf(stderr, "Usage: %s [-cih]\n", argv[0]);
                fprintf(stderr, " -c | --continue   On error, continue to the next unit_test.\n");
                fprintf(stderr, " -i | --ignore     On error, ignore it and continue.\n");
                fprintf(stderr, " -v | --verbose    Show the result of every test.\n");
                fprintf(stderr, " -q | --quiet      Do not print report at the end.\n");
                fprintf(stderr, " -h | --help       Print this help.\n");
                return -1;
        }
    }

    kcrypt_initialize(KC_QUICK_RANDOM | KC_NO_SECMEM);

    signal(SIGSEGV, signal_handler);

    for (func = unit_test_array; *func != NULL; func++) {
        int jmp_ret = setjmp(exception_buf);
        if (jmp_ret == 0) 
            start_unit_test(*func);
        else if (jmp_ret == 1)
            continue;
        else
            break;
    }

    if (!quiet) {
        printf("%i errors / %i asserts\n", nb_error, nb_assert);
    }

    kcrypt_finalize();
    return 0;
}
