// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2018, NetApp, Inc.
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

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>

#include <warpcore/warpcore.h>

#include "diet.h"


/// Compare two ival intervals.
///
/// @param[in]  a     Interval one.
/// @param[in]  b     Interval two.
///
/// @return     Zero if a is in b or b is in a. Negative if a's lower bound is
///             less than b's lower bound, positive otherwise.
///
int ival_cmp(const struct ival * const a, const struct ival * const b)
{
    if ((a->lo >= b->lo && a->lo <= b->hi) ||
        (b->lo >= a->lo && b->lo <= a->hi))
        return 0;
    return (a->lo > b->lo) - (a->lo < b->lo);
}


SPLAY_GENERATE(diet, ival, node, ival_cmp)


/// Absolute minimal distance of @p n from the interval @p i,. i.e., either its
/// lower or upper boundary.
///
/// @param[in]  n     Integer.
/// @param[in]  i     Interval.
///
/// @return     Zero if @p n is inside @p i. Absolute minimal distance of @p n
///             from the closes bound otherwise.
///
static uint64_t ival_dist(const uint64_t n, const struct ival * const i)
{
    if (i == 0)
        return UINT64_MAX;
    if (n >= i->lo && n <= i->hi)
        return 0;
    return MIN(n > i->lo ? n - i->lo : i->lo - n,
               n > i->hi ? n - i->hi : i->hi - n);
}


/// Return maximum interval underneath @p i.
///
/// @param      i     Interval inside diet tree.
///
/// @return     Largest interval underneath @p i.
///
static struct ival * find_max(struct ival * const i)
{
    if (i == 0)
        return 0;
    struct ival * n = i;
    while (splay_right(n, node))
        n = splay_right(n, node);
    return n;
}


/// Return minimum interval underneath @p i.
///
/// @param      i     Interval inside diet tree.
///
/// @return     Smallest interval underneath @p i.
///
static struct ival * find_min(struct ival * const i)
{
    if (i == 0)
        return 0;
    struct ival * n = i;
    while (splay_left(n, node))
        n = splay_left(n, node);
    return n;
}


/// Pointer to the interval containing @p n in diet tree @p t. Also has the side
/// effect of splaying the closest interval to @p n to the root of @p t.
///
/// @param      d     Diet tree.
/// @param[in]  n     Integer.
///
/// @return     Pointer to the ival structure containing @p i; zero otherwise.
///
struct ival * diet_find(struct diet * const d, const uint64_t n)
{
    if (splay_empty(d))
        return 0;

    diet_splay(d, &(const struct ival){.lo = n, .hi = n});

    // Due to the way a splay works with intervals, n will be closest to (or
    // contained in) either the root node interval after a splay operation, or
    // in its maximum left or minimum right child. In the latter case, rotate
    // that child to the root, to make sure n is always closest to (or inside)
    // the root interval.

    const uint64_t d_left =
        ival_dist(n, find_max(splay_left(splay_root(d), node)));
    const uint64_t d_right =
        ival_dist(n, find_min(splay_right(splay_root(d), node)));
    const uint64_t d_root = ival_dist(n, splay_root(d));

    if (d_left < d_root && d_left < d_right) {
        struct ival * const left = splay_left(splay_root(d), node);
        splay_rotate_right(d, left, node);
    } else if (d_right < d_root && d_right < d_left) {
        struct ival * const right = splay_right(splay_root(d), node);
        splay_rotate_left(d, right, node);
    }

    if (n < splay_root(d)->lo || n > splay_root(d)->hi)
        return 0;
    return splay_root(d);
}


/// Helper function to create a zero-width interval containing (only) @p n.
///
/// @param[in]  n     Integer.
/// @param[in]  t     Type.
///
/// @return     Newly allocated ival struct [n..n] of type @p t.
///
static struct ival * make_ival(const uint64_t n, const uint8_t t)
{
    struct ival * const i = calloc(1, sizeof(*i));
    ensure(i, "could not calloc");
    i->lo = i->hi = n;
    i->type = t;
    splay_left(i, node) = splay_right(i, node) = 0;
    return i;
}


/// Inserts integer @p n of type @p t into the diet tree @p t.
///
/// @param      d     Diet tree.
/// @param[in]  n     Integer.
/// @param[in]  t     Type.
///
/// @return     Pointer to ival containing @p n.
///
struct ival *
diet_insert(struct diet * const d, const uint64_t n, const uint8_t t)
{
    if (splay_empty(d)) {
        d->cnt++;
        return splay_root(d) = make_ival(n, t);
    }

    // rotate the interval that contains n or is closest to it to the top
    diet_find(d, n);

    warn(DBG, "root %u.%u-%u", splay_root(d)->type, splay_root(d)->lo, splay_root(d)->hi);

    if (n < splay_root(d)->lo) {
        if (n + 1 == splay_root(d)->lo && t == splay_root(d)->type) {
            splay_root(d)->lo--;
            if (splay_left(splay_root(d), node)) {
                struct ival * const max =
                    find_max(splay_left(splay_root(d), node));
                if (max->hi + 1 == splay_root(d)->lo &&
                    max->type == splay_root(d)->type) {
                    splay_root(d)->lo = max->lo;
                    splay_left(splay_root(d), node) = splay_left(max, node);
                    free(max);
                    d->cnt--;
                }
            }
            return splay_root(d);
        }
        struct ival * const i = make_ival(n, t);
        splay_insert(diet, d, i);
        d->cnt++;
        return i;
    }

    if (n > splay_root(d)->hi) {
        if (n == splay_root(d)->hi + 1 && t == splay_root(d)->type) {
            splay_root(d)->hi++;
            if (splay_right(splay_root(d), node)) {
                struct ival * const min =
                    find_min(splay_right(splay_root(d), node));
                if (min->lo - 1 == splay_root(d)->hi &&
                    min->type == splay_root(d)->type) {
                    splay_root(d)->hi = min->hi;
                    splay_right(splay_root(d), node) = splay_right(min, node);
                    free(min);
                    d->cnt--;
                }
            }
            return splay_root(d);
        }
        struct ival * const i = make_ival(n, t);
        splay_insert(diet, d, i);
        d->cnt++;
        return i;
    }

    return splay_root(d);
}


/// Remove integer @p n from the intervals stored in diet tree @p t.
///
/// @param      d     Diet tree.
/// @param[in]  n     Integer.
///
void diet_remove(struct diet * const d, const uint64_t n)
{
    // rotate the interval that contains n or is closest to it to the top
    diet_find(d, n);

    if (n < splay_root(d)->lo || n > splay_root(d)->hi)
        return;

    if (n == splay_root(d)->lo) {
        if (n == splay_root(d)->hi) {
            free(splay_remove(diet, d, splay_root(d)));
            d->cnt--;
        } else
            // adjust lo bound
            splay_root(d)->lo++;
    } else if (n == splay_root(d)->hi) {
        // adjust hi bound
        splay_root(d)->hi--;
    } else {
        // split interval
        struct ival * const i =
            make_ival(splay_root(d)->lo, splay_root(d)->type);
        d->cnt++;
        i->hi = n - 1;
        splay_root(d)->lo = n + 1;
        splay_left(i, node) = splay_left(splay_root(d), node);
        splay_left(splay_root(d), node) = 0;
        splay_right(i, node) = splay_root(d);
        splay_root(d) = i;
    }
}


void diet_free(struct diet * const d)
{
    struct ival *i, *next;
    for (i = splay_min(diet, d); i != 0; i = next) {
        next = splay_next(diet, d, i);
        splay_remove(diet, d, i);
        free(i);
    }
}


size_t diet_to_str(char * const str, const size_t len, struct diet * const d)
{
    struct ival * i = 0;
    size_t pos = 0;
    str[0] = 0;
    splay_foreach (i, diet, d) {
        pos += (size_t)snprintf(&str[pos], len - pos, "%u.%" PRIu64, i->type,
                                i->lo);
        if (i->lo != i->hi)
            pos += (size_t)snprintf(&str[pos], len - pos, "-%" PRIu64, i->hi);
        pos += (size_t)snprintf(&str[pos], len - pos, ", ");
    }
    if (pos > 2) {
        pos -= 2;
        str[pos] = 0; // strip final comma and space
    }
    return pos;
}
