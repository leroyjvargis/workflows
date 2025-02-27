/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_test_support/random_buffer.h>
#include <hse_util/xrand.h>

#include <string.h>

void
randomize_buffer(void *buf, size_t len, unsigned int seed)
{
    unsigned int *  tmp = (unsigned int *)buf;
    u_int           last;
    long int        remain = len;
    int             i;
    struct xrand xr;

    if (len == 0)
        return;

    xrand_init(&xr, seed);
    for (i = 0; remain > 0; i++, remain -= sizeof(*tmp)) {
        if (remain > sizeof(*tmp)) { /* likely */
            tmp[i] = xrand64(&xr);
        } else { /* unlikely */
            last = xrand64(&xr);
            memcpy(&tmp[i], &last, remain);
        }
    }
}

int
validate_random_buffer(void *buf, size_t len, unsigned int seed)
{
    unsigned int *  tmp = (unsigned int *)buf;
    unsigned int    val;
    char *          expect = (char *)&val;
    char *          found;
    long int        remain = len;
    int             i;
    struct xrand xr;

    if (len == 0)
        return -1; /* success... */

    xrand_init(&xr, seed);
    for (i = 0; remain > 0; i++, remain -= sizeof(*tmp)) {
        val = xrand64(&xr);
        if ((remain >= sizeof(*tmp)) && (val != tmp[i])) { /* Likely */
            return ((int)(len - remain));
        } else if (remain < sizeof(*tmp)) { /* Unlikely */
            found = (char *)&tmp[i];
            if (memcmp(expect, found, remain)) {
                /*
                 * [HSE_REVISIT]
                 * Miscompare offset might be off here
                 */
                return ((int)(len - remain));
            }
        }
    }
    /* -1 is success, because 0..n are valid offsets for an error */
    return -1;
}

/* Get a random value in the range [min, max]. Note that the max is an inclusive upper bound.
 */
u32
generate_random_u32(u32 min, u32 max)
{
    return (xrand64_tls() % (max - min + 1)) + min;
}

void
permute_u32_sequence(u32 *values, u32 num_values)
{
    u32 i, j, tmp_val;

    for (i = num_values - 1; i > 0; --i) {
        j = generate_random_u32(0, i - 1);
        tmp_val = values[i];
        values[i] = values[j];
        values[j] = tmp_val;
    }
}

void
generate_random_u32_sequence(u32 min_value, u32 max_value, u32 *values, u32 num_values)
{
    u32 i;

    for (i = 0; i < num_values; ++i)
        values[i] = generate_random_u32(min_value, max_value);

    permute_u32_sequence(values, num_values);
}

void
generate_random_u32_sequence_unique(u32 min_value, u32 max_value, u32 *values, u32 num_values)
{
    u32 i;
    u32 stride = (max_value - min_value) / num_values;

    assert(stride > 0);

    for (i = 0; i < num_values; ++i) {
        u32 min = i * stride;
        u32 max = min + stride - 1;

        if (i == num_values - 1)
            max = max_value;

        values[i] = generate_random_u32(min, max);
    }

    permute_u32_sequence(values, num_values);
}
