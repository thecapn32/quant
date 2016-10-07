#pragma once

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

// ANSI escape sequences (color, etc.)
#define NRM "\x1B[0m"  // reset all to normal
#define BLD "\x1B[1m"  // bold
#define DIM "\x1B[2m"  // dim
#define ULN "\x1B[3m"  // underline
#define BLN "\x1B[5m"  // blink
#define REV "\x1B[7m"  // reverse
#define HID "\x1B[8m"  // hidden
#define BLK "\x1B[30m" // black
#define RED "\x1B[31m" // red
#define GRN "\x1B[32m" // green
#define YEL "\x1B[33m" // yellow
#define BLU "\x1B[34m" // blue
#define MAG "\x1B[35m" // magenta
#define CYN "\x1B[36m" // cyan
#define WHT "\x1B[37m" // white

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpedantic"

#ifndef NDEBUG

#include <regex.h>

enum dlevel { crit = 0, err = 1, warn = 2, notice = 3, info = 4, debug = 5 };

// Set DLEVEL to the level of debug output you want to see in the Makefile
#ifndef DLEVEL
#define DLEVEL debug
#endif

// Set DCOMPONENT to a regex matching the components (files) you want to see
// debug output from in the Makefile
#ifndef DCOMPONENT
#define DCOMPONENT ".*"
#endif

// Trim the path from the given file name (to be used with __FILE__)
#define BASENAME(f) (strrchr((f), '/') ? strrchr((f), '/') + 1 : (f))


extern const char * const col[];
extern regex_t            _comp;
extern struct timeval     _epoch;

extern int timeval_subtract(struct timeval * const result,
                            struct timeval * const x,
                            struct timeval * const y);


// These macros are based on the "D" ones defined by netmap
#define warn(dlevel, fmt, ...)                                                 \
    if (DLEVEL >= dlevel && !regexec(&_comp, __FILE__, 0, 0, 0)) {             \
        struct timeval _now, _elapsed;                                         \
        gettimeofday(&_now, 0);                                                \
        timeval_subtract(&_elapsed, &_now, &_epoch);                           \
        fprintf(stderr, REV "%s " NRM "% 2ld.%04ld" MAG " %s" BLK "@" BLU      \
                            "%s:%d " NRM fmt "\n",                             \
                col[dlevel], (long)(_elapsed.tv_sec % 1000),                   \
                (long)(_elapsed.tv_usec / 1000), __func__, BASENAME(__FILE__), \
                __LINE__, ##__VA_ARGS__);                                      \
        fflush(stderr);                                                        \
    }

// Rate limited version of "log", lps indicates how many per second
#define rwarn(dlevel, lps, format, ...)                                        \
    if (DLEVEL >= dlevel && !regexec(&_comp, __FILE__, 0, 0, 0)) {             \
        static time_t  _rt0, _rcnt;                                            \
        struct timeval _rts;                                                   \
        gettimeofday(&_rts, 0);                                                \
        if (_rt0 != _rts.tv_sec) {                                             \
            _rt0 = _rts.tv_sec;                                                \
            _rcnt = 0;                                                         \
        }                                                                      \
        if (_rcnt++ < lps)                                                     \
            warn(dlevel, format, ##__VA_ARGS__);                               \
    }

#else

#define warn(fmt, ...)                                                         \
    do {                                                                       \
    } while (0)
#define rwarn(fmt, ...)                                                        \
    do {                                                                       \
    } while (0)

#endif

// Abort execution with a message
#define die(fmt, ...)                                                          \
    do {                                                                       \
        const int      _e = errno;                                             \
        struct timeval _now, _elapsed;                                         \
        gettimeofday(&_now, 0);                                                \
        timeval_subtract(&_elapsed, &_now, &_epoch);                           \
        fprintf(stderr, RED BLD REV " % 2ld.%04ld %s@%s:%d ABORT: " fmt        \
                                    " %c%s%c\n" NRM,                           \
                (long)(_elapsed.tv_sec % 1000),                                \
                (long)(_elapsed.tv_usec / 1000), __func__, BASENAME(__FILE__), \
                __LINE__, ##__VA_ARGS__, (_e ? '[' : 0),                       \
                (_e ? strerror(_e) : ""), (_e ? '[' : 0));                     \
        abort();                                                               \
    } while (0)

// A version of the assert() macro that isn't disabled by NDEBUG and that uses
// our other debug functions
#define assert(e, fmt, ...)                                                    \
    do {                                                                       \
        if (!(e)) {                                                            \
            die("assertion failed \n         " #e " \n         " fmt,          \
                ##__VA_ARGS__);                                                \
        }                                                                      \
    } while (0)


#pragma GCC diagnostic pop

extern void hexdump(const void * const ptr, const size_t len);
