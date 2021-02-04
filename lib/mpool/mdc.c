/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <fcntl.h>

#include <hse_util/event_counter.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>

#include "mpool.h"
#include "mdc.h"
#include "mdc_file.h"

merr_t
mpool_mdc_alloc2(
	struct mpool           *mp,
    u32                     magic,
    size_t                  capacity,
	enum mp_media_classp    mclassp,
    uint64_t               *logid1,
    uint64_t               *logid2)
{
    enum mclass_id mcid;
	merr_t err;
    uint64_t id[2];
    int i, dirfd, flags, mode;

    mcid = mclassp;
    if (ev(!mp || mcid >= MCID_MAX))
        return merr(EINVAL);

    dirfd = mclass_dirfd(mpool_mchdl_get(mp, mcid));
    flags = O_RDWR | O_CREAT | O_EXCL;
    mode = S_IRUSR | S_IWUSR;

    for (i = 0; i < 2; i++) {
        id[i] = logid_make(i, mclassp, magic);

        err = mdc_file_create(dirfd, id[i], flags, mode, capacity);
        if (ev(err)) {
            if (i != 0)
                mdc_file_destroy(dirfd, id[0]);
            return err;
        }
    }

    *logid1 = id[0];
    *logid2 = id[1];

    return 0;
}

merr_t
mpool_mdc_commit2(struct mpool *mp, uint64_t logid1, uint64_t logid2)
{
    enum mclass_id mcid;
	merr_t err;
    int dirfd, i;
    uint64_t id[] = {logid1, logid2};;

    if (ev(!mp || !logids_valid(logid1, logid2)))
        return merr(EINVAL);

    mcid = logid_mcid(logid1);
    dirfd = mclass_dirfd(mpool_mchdl_get(mp, mcid));

    for (i = 0; i < 2; i++) {
        err = mdc_file_commit(dirfd, id[i]);
        if (ev(err)) {
            while (i >= 0)
                mdc_file_destroy(dirfd, id[i--]);
            return merr(err);
        }
    }

	return 0;
}

merr_t
mpool_mdc_delete2(struct mpool *mp, uint64_t logid1, uint64_t logid2)
{
    enum mclass_id mcid;
    merr_t err, rval=0;
    int dirfd, i;
    uint64_t id[] = {logid1, logid2};;

    if (ev(!mp || !logids_valid(logid1, logid2)))
        return merr(EINVAL);

    mcid = logid_mcid(logid1);
    dirfd = mclass_dirfd(mpool_mchdl_get(mp, mcid));

    for (i = 0; i < 2; i++) {
        err = mdc_file_destroy(dirfd, id[i]);
        if (ev(err))
            rval = err;
    }

    return rval;
}

merr_t
mpool_mdc_abort2(struct mpool *mp, uint64_t logid1, uint64_t logid2)
{
    return mpool_mdc_delete2(mp, logid1, logid2);
}
