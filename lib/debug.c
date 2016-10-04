#include <ctype.h>
#include <stdio.h>

#include "debug.h"

#ifndef NDEBUG

const char * const col[] = {MAG, RED, YEL, CYN, BLU, GRN};

regex_t _comp;


// Initialize the regular expression used for restricting debug output
static void __attribute__((constructor)) premain()
{
    if (regcomp(&_comp, DCOMPONENT, REG_EXTENDED | REG_ICASE | REG_NOSUB))
        die("may not be a valid regexp: %s", DCOMPONENT);
}


// And free is again
static void __attribute__((destructor)) postmain() { regfree(&_comp); }


// Print a hexdump of the given block
void hexdump(const void * const ptr, const size_t len)
{
    const uint8_t * const buf = ptr;
    for (uint8_t i = 0; i < len; i += 16) {
        fprintf(stderr, "%06x: ", i);
        for (uint8_t j = 0; j < 16; j++) {
            if (i + j < len)
                fprintf(stderr, "%02hhx ", buf[i + j]);
            else
                fprintf(stderr, "   ");
            fprintf(stderr, " ");
        }
        for (uint8_t j = 0; j < 16; j++) {
            if (i + j < len)
                fprintf(stderr, "%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        }
        fprintf(stderr, "\n");
    }
}

#endif
