// Copyright (c) 2016-2017, NetApp, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#pragma once


#ifndef NDEBUG
#define PTHREAD_MUTEX_TYPE PTHREAD_MUTEX_ERRORCHECK
#else
#define PTHREAD_MUTEX_TYPE PTHREAD_MUTEX_DEFAULT
#endif

#define mutex_init(m)                                                          \
    do {                                                                       \
        pthread_mutexattr_t attr;                                              \
        ensure(pthread_mutexattr_init(&attr) == 0, "pthread_mutexattr_init");  \
        ensure(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_TYPE) == 0,      \
               "pthread_mutexattr_settype");                                   \
        ensure(pthread_mutex_init(m, &attr) == 0, "pthread_mutex_init");       \
        ensure(pthread_mutexattr_destroy(&attr) == 0,                          \
               "pthread_mutexattr_destroy");                                   \
    } while (0)


#define mutex_destroy(m)                                                       \
    do {                                                                       \
        ensure(pthread_mutex_destroy(m) == 0, "pthread_mutex_destroy");        \
    } while (0)


#define lock(l)                                                                \
    do {                                                                       \
        const int ret_lock = pthread_mutex_lock(l);                            \
        ensure(ret_lock == 0, "pthread_mutex_lock returned %d (%s)", ret_lock, \
               strerror(ret_lock));                                            \
    } while (0)


#define unlock(l)                                                              \
    do {                                                                       \
        const int ret_unlock = pthread_mutex_unlock(l);                        \
        ensure(ret_unlock == 0, "pthread_mutex_unlock returned %d (%s)",       \
               ret_unlock, strerror(ret_unlock));                              \
    } while (0)


#define cond_init(c)                                                           \
    do {                                                                       \
        ensure(pthread_cond_init(c, 0) == 0, "pthread_cond_init");             \
    } while (0)


#define cond_destroy(c)                                                        \
    do {                                                                       \
        ensure(pthread_cond_destroy(c) == 0, "pthread_cond_destroy");          \
    } while (0)


#define signal(c, l)                                                           \
    do {                                                                       \
        const int ret_cs = pthread_cond_signal(c);                             \
        ensure(ret_cs == 0, "pthread_cond_signal returned %d (%s)", ret_cs,    \
               strerror(ret_cs));                                              \
    } while (0)


#define wait(c, l)                                                             \
    do {                                                                       \
        const int ret_cw = pthread_cond_wait(c, l);                            \
        ensure(ret_cw == 0, "pthread_cond_wait returned %d (%s)", ret_cw,      \
               strerror(ret_cw));                                              \
    } while (0)
