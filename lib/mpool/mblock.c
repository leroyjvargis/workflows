/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <hse_util/event_counter.h>
#include <hse_util/logging.h>

#include "mpool.h"
#include "mclass.h"
#include "mblock_fset.h"
#include "mblock_file.h"

struct mpool;

merr_t
mpool_mblock_alloc2(
    struct mpool           *mp,
    enum mp_media_classp	mclass,
    uint64_t               *mbid,
    struct mblock_props    *props)
{
    struct media_class *mc;
    enum mclass_id mcid;

    merr_t err;

    mcid = mclass_to_id(mclass);

    if (ev(!mp || !mbid || mcid >= MCID_MAX))
        return merr(EINVAL);

    mc = mpool_mchdl_get(mp, mcid);

    err = mblock_fset_alloc(mclass_fset(mc), 1, mbid);

    if (!err && props) {
        props->mpr_objid = *mbid;
        props->mpr_alloc_cap = MBLOCK_SIZE_MB << 20;
        props->mpr_optimal_wrsz = 128 << 10;
        props->mpr_mclassp = mclass;
    }

    return err;
}

merr_t
mpool_mblock_commit(struct mpool *mp, uint64_t mbid)
{
    struct media_class *mc;
    enum mclass_id mcid;

    if (ev(!mp))
        return merr(EINVAL);

    mcid = mbid & MBID_MCID_MASK;
    mc = mpool_mchdl_get(mp, mcid);

    return mblock_fset_commit(mclass_fset(mc), &mbid, 1);
}

merr_t
mpool_mblock_abort(struct mpool *mp, uint64_t mbid)
{
    struct media_class *mc;
    enum mclass_id mcid;

    if (ev(!mp))
        return merr(EINVAL);

    mcid = mbid & MBID_MCID_MASK;
    mc = mpool_mchdl_get(mp, mcid);

    return mblock_fset_abort(mclass_fset(mc), &mbid, 1);
}

merr_t
mpool_mblock_delete(struct mpool *mp, uint64_t mbid)
{
    struct media_class *mc;
    enum mclass_id mcid;

    if (ev(!mp))
        return merr(EINVAL);

    mcid = mbid & MBID_MCID_MASK;
    mc = mpool_mchdl_get(mp, mcid);

    return mblock_fset_delete(mclass_fset(mc), &mbid, 1);
}

merr_t
mpool_mblock_find(struct mpool *mp, uint64_t mbid, struct mblock_props *props)
{
    struct media_class *mc;
    enum mclass_id mcid;

    merr_t err;

    if (ev(!mp))
        return merr(EINVAL);

    mcid = mbid & MBID_MCID_MASK;
    mc = mpool_mchdl_get(mp, mcid);

    err = mblock_fset_find(mclass_fset(mc), &mbid, 1);

    if (!err && props) {
        props->mpr_objid = mbid;
        props->mpr_alloc_cap = MBLOCK_SIZE_MB << 20;
        props->mpr_optimal_wrsz = 128 << 10;
        props->mpr_mclassp = (enum mp_media_classp)mcid; /* TODO: fix this */
    }

    return err;
}


merr_t
mpool_mblock_write2(
    struct mpool       *mp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off)
{
    struct media_class *mc;
    enum mclass_id      mcid;

    if (ev(!mp || !iov))
        return merr(EINVAL);

    mcid = mbid & MBID_MCID_MASK;
    mc = mpool_mchdl_get(mp, mcid);

    return mblock_fset_write(mclass_fset(mc), mbid, iov, iovc, off);
}

merr_t
mpool_mblock_read(
    struct mpool       *mp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off)
{
    struct media_class *mc;
    enum mclass_id mcid;

    if (ev(!mp || !iov))
        return merr(EINVAL);

    mcid = mbid & MBID_MCID_MASK;
    mc = mpool_mchdl_get(mp, mcid);

    return mblock_fset_read(mclass_fset(mc), mbid, iov, iovc, off);
}
