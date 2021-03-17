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
#include "mblock_fset.h"
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

enum param_key_index {
    PARAM_PATH     = 0,
    PARAM_ENV_PATH = 1,
    PARAM_OBJSZ    = 2,
    PARAM_FCNT     = 3,
    PARAM_FSIZE    = 4,
    PARAM_MAX      = 5,
};

static const char *param_key[PARAM_MAX][MP_MED_COUNT] =
{
    { "kvdb.storage_path", "kvdb.staging_path" },
    { "HSE_STORAGE_PATH", "HSE_STAGING_PATH" },
    { "kvdb.storage_objsz", "kvdb.staging_objsz" },
    { "kvdb.storage_filecnt", "kvdb.staging_filecnt" },
    { "kvdb.storage_filesz", "kvdb.staging_filesz" },
};

static merr_t
mclass_params_init(enum mp_media_classp mclass, struct mclass_params *mparams)
{
    char *path;

    path = getenv(param_key[PARAM_ENV_PATH][mclass]);
    if (path) {
        size_t n;

        n = strlcpy(mparams->path, path, sizeof(mparams->path));
        if (n >= sizeof(mparams->path))
            return merr(EINVAL);
    }

    mparams->mblocksz = MBLOCK_SIZE_BYTES;
    mparams->filecnt = MBLOCK_FSET_FILES_DEFAULT;
    mparams->fszmax = MBLOCK_FILE_SIZE_MAX;

    return 0;
}

static merr_t
hse_to_mclass_params(
    const struct hse_params *hparams,
    enum mp_media_classp     mclass,
    struct mclass_params    *mparams)
{
    char buf[PATH_MAX];

    if (!hparams)
        return 0;

    if (hse_params_get(hparams, param_key[PARAM_PATH][mclass], buf, sizeof(buf), NULL) &&
        buf[0] != '\0') {
        size_t n;

        n = strlcpy(mparams->path, buf, sizeof(mparams->path));
        if (n >= sizeof(mparams->path))
            return merr(EINVAL);
    }

    if (hse_params_get(hparams, param_key[PARAM_OBJSZ][mclass], buf, sizeof(buf), NULL) &&
        buf[0] != '\0') {
        mparams->mblocksz = atoi(buf);
        mparams->mblocksz <<= 20;
    }

    if (hse_params_get(hparams, param_key[PARAM_FCNT][mclass], buf, sizeof(buf), NULL) &&
        buf[0] != '\0')
        mparams->filecnt = atoi(buf);

    if (hse_params_get(hparams, param_key[PARAM_FSIZE][mclass], buf, sizeof(buf), NULL) &&
        buf[0] != '\0') {
        mparams->fszmax = atoi(buf);
        mparams->fszmax <<= 30;
    }

    return 0;
}

merr_t
mpool_open(const char *name, const struct hse_params *params, uint32_t flags, struct mpool **handle)
{
    struct mpool *mp;
    merr_t        err;
    int           i;

    *handle = NULL;

    if (ev(!name || !handle))
        return merr(EINVAL);

    mp = calloc(1, sizeof(*mp));
    if (ev(!mp))
        return merr(ENOMEM);


    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        struct mclass_params mparams = {};

        err = mclass_params_init(i, &mparams);
        if (err)
            goto errout;

        err = hse_to_mclass_params(params, i, &mparams);
        if (err)
            goto errout;

        if (mparams.path[0] != '\0') {
            err = mclass_open(mp, i, &mparams, flags, &mp->mc[i]);
            if (ev(err)) {
                hse_log(
                    HSE_ERR "%s: Malformed storage path for mclass %d", __func__, i);
                goto errout;
            }
        } else if (i == MP_MED_CAPACITY) {
            err = merr(EINVAL);
            hse_log(HSE_ERR "%s: storage path not set for %s", __func__, name);
            goto errout;
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
    struct media_class *mc;

    if (mclass >= MP_MED_COUNT)
        return merr(EINVAL);

    mc = mp->mc[mclass];
    if (!mc)
        return merr(ENOENT);

    if (props)
        props->mc_mblocksz = mclass_mblocksz(mc) >> 20;

    return 0;
}

merr_t
mpool_props_get(struct mpool *mp, struct mpool_props *props)
{
    int i;

    memset(props, 0, sizeof(*props));

    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        struct media_class *mc;

        mc = mp->mc[i];
        if (mc)
            props->mp_mblocksz[i] = mclass_mblocksz(mc) >> 20;
    }

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
