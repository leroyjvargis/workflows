/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_mpool

#include <stdlib.h>

#include <hse_util/logging.h>
#include <hse_util/event_counter.h>
#include <hse_util/hse_err.h>
#include <hse_util/string.h>

#include <hse/hse.h>
#include <mpool/mpool.h>
#include <mpool/mpool_internal.h>

#include "mpool.h"
#include "mblock_file.h"
#include "mdc.h"

#define UUID_STRLEN 36

/**
 * struct mpool - mpool handle
 *
 * @mc:       media class handles
 * @name:     mpool/kvdb name
 */
struct mpool {
    struct media_class *mc[MP_MED_COUNT];

    char name[64];
};

merr_t
mpool_open(const char *name, const struct hse_params *params, uint32_t flags, struct mpool **handle)
{
    struct mpool *mp;

    const char *param_key[MP_MED_COUNT] = { "kvdb.capdir", "kvdb.stgdir" };
    const char *env_key[MP_MED_COUNT] = { "HSE_STORAGE_PATH", "HSE_STORAGE_STAGING_PATH" };
    char        fbuf[4];
    merr_t      err;
    int         i, fcnt = 0;

    *handle = NULL;

    if (ev(!name || !handle))
        return merr(EINVAL);

    mp = calloc(1, sizeof(*mp));
    if (ev(!mp))
        return merr(ENOMEM);

    /* Extract the experimental filecnt parameter */
    if (params && hse_params_get(params, "kvdb.filecnt", fbuf, sizeof(fbuf), NULL)) {
        if (fbuf[0] != '\0')
            fcnt = atoi(fbuf);
    }

    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        char dpath[PATH_MAX], *path;

        /* cli args override env. */
        path = getenv(env_key[i]);
        if (params &&
            hse_params_get(params, param_key[i], dpath, sizeof(dpath), NULL) && dpath[0] != '\0')
            path = dpath;

        if (path) {
            err = mclass_open(mp, i, path, fcnt, flags, &mp->mc[i]);
            if (ev(err)) {
                hse_log(
                    HSE_ERR "%s: Malformed storage path for mclass %d", __func__, i);
                goto errout;
            }
        } else {
            if (i == MP_MED_CAPACITY) {
                err = merr(EINVAL);
                hse_log(HSE_ERR "%s: Capacity mclass path is missing for mpool %s", __func__, name);
                goto errout;
            }
        }
    }

    strlcpy(mp->name, name, sizeof(mp->name));

    err = mpool_mdc_root_init(mp);
    if (ev(err))
        goto errout;

    *handle = mp;

    return 0;

errout:
    while (i-- > MP_MED_BASE)
        mclass_close(mp->mc[i]);

    free(mp);

    return err;
}

merr_t
mpool_close(struct mpool *mp)
{
    merr_t err = 0;
    int    i;

    if (ev(!mp))
        return merr(EINVAL);

    for (i = MP_MED_COUNT - 1; i >= MP_MED_BASE; i--) {
        if (mp->mc[i]) {
            err = mclass_close(mp->mc[i]);
            if (err)
                hse_log(HSE_ERR "%s: Closing mclass id %d failed", __func__, i);
        }
    }

    free(mp);

    return err;
}

merr_t
mpool_destroy(struct mpool *mp)
{
    int i;

    if (ev(!mp))
        return merr(EINVAL);

    mpool_mdc_root_destroy(mp);

    for (i = MP_MED_COUNT - 1; i >= MP_MED_BASE; i--) {
        if (mp->mc[i])
            mclass_destroy(mp->mc[i]);
    }

    free(mp);

    return 0;
}

merr_t
mpool_mclass_get(struct mpool *mp, enum mp_media_classp mclass, struct mpool_mclass_props *props)
{
    if (mclass >= MP_MED_COUNT)
        return merr(EINVAL);

    if (!mp->mc[mclass])
        return merr(ENOENT);

    if (props)
        props->mc_mblocksz = MBLOCK_SIZE_MB;

    return 0;
}

merr_t
mpool_props_get(struct mpool *mp, struct mpool_props *props)
{
    int i;

    memset(props, 0, sizeof(*props));

    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++)
        props->mp_mblocksz[i] = MBLOCK_SIZE_MB;

    props->mp_vma_size_max = 30;

    return 0;
}

struct media_class *
mpool_mclass_handle(struct mpool *mp, enum mp_media_classp mclass)
{
    assert(mclass < MP_MED_COUNT);
    return mp->mc[mclass];
}

merr_t
mpool_usage_get(struct mpool *mp, struct mpool_usage *usage)
{
    return 0;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "mpool_ut_impl.i"
#endif
