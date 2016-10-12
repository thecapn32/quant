#include <ctype.h>
#include <stdint.h>
#include <stdio.h>

#include "util.h"

#ifndef NDEBUG

const char * const col[] = {MAG, RED, YEL, CYN, BLU, GRN};

regex_t _comp;

struct timeval _epoch;

static void __attribute__((constructor)) premain()
{
    // Initialize the regular expression used for restricting debug output
    if (regcomp(&_comp, DCOMPONENT, REG_EXTENDED | REG_ICASE | REG_NOSUB))
        die("may not be a valid regexp: %s", DCOMPONENT);

    // Get the current time
    gettimeofday(&_epoch, 0);
}


static void __attribute__((destructor)) postmain()
{
    // Free the regular expression used for restricting debug output
    regfree(&_comp);
}


int __attribute__((nonnull)) timeval_subtract(struct timeval * const result,
                                              struct timeval * const x,
                                              struct timeval * const y)
{
    // Perform the carry for the later subtraction by updating y.
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    // Compute the time remaining to wait. tv_usec is certainly positive.
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    // /* Return 1 if result is negative.
    return x->tv_sec < y->tv_sec;
}

#endif


// Print a hexdump of the given block
void __attribute__((nonnull)) hexdump(const void * const ptr, const size_t len)
{
    const uint8_t * const buf = ptr;
    for (size_t i = 0; i < len; i += 16) {
        fprintf(stderr, "%06lx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                fprintf(stderr, "%02hhx ", buf[i + j]);
            else
                fprintf(stderr, "   ");
            fprintf(stderr, " ");
        }
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                fprintf(stderr, "%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        }
        fprintf(stderr, "\n");
    }
}
