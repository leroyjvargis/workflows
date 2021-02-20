/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ftw.h>

#include <hse_util/event_counter.h>
#include <hse_util/logging.h>

#include "mclass.h"
#include "mblock_fset.h"

/**
 * struct mblock_fset - mblock fileset instance
 *
 * @mc:        media class handle
 * @filev:     vector of mblock file handles
 * @filec:     mblock file count
 * @meta_fd:   fd of the fileset meta file
 * @meta_name: fileset meta file name
 */
struct mblock_fset {
    struct media_class  *mc;

    atomic64_t           fidx;
    struct mblock_file **filev;
    int                  filec;

    int                  meta_fd;
    char                 meta_name[32];
};


/* Init metadata file that persists mblocks in the data files */
static merr_t
mblock_fset_meta_open(struct mblock_fset *mbfsp)
{
    char name[32];
    int  fd;
    merr_t err;

    snprintf(name, sizeof(name), "%s", "mblock-meta");

    fd = openat(mclass_dirfd(mbfsp->mc), name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        hse_elog(HSE_ERR "open/create meta file failed, mclass dir %s: @@e",
                 err, mclass_dpath(mbfsp->mc));
    }

    mbfsp->meta_fd = fd;

    return 0;
}

static void
mblock_fset_meta_close(struct mblock_fset *mbfsp)
{
    close(mbfsp->meta_fd);
}

static void
mblock_fset_meta_remove(const char *dpath)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/%s", dpath, "mblock-meta");

    remove(path);
}

merr_t
mblock_fset_open(struct media_class *mc, int flags, struct mblock_fset **handle)
{
    struct mblock_fset *mbfsp;

    size_t sz;
    merr_t err;
    int    i = 0;

    if (ev(!mc || !handle))
        return merr(EINVAL);

    sz = sizeof(*mbfsp) + MBLOCK_FSET_FILES_DEFAULT * sizeof(void *);

    mbfsp = calloc(1, sz);
    if (ev(!mbfsp))
        return merr(ENOMEM);

    mbfsp->mc = mc;
    atomic64_set(&mbfsp->fidx, 0);
    mbfsp->filec = MBLOCK_FSET_FILES_DEFAULT;
    mbfsp->filev = (void *)(mbfsp + 1);

    for (i = 0; i < mbfsp->filec; i++) {
        char name[32];

        snprintf(name, sizeof(name), "%s-%d-%d", "mblock-data", mclass_id(mc), i + 1);

        err = mblock_file_open(mbfsp, mclass_dirfd(mc), mclass_id(mc), i + 1, name,
                               flags, &mbfsp->filev[i]);
        if (ev(err))
            goto err_exit;
    }

    err = mblock_fset_meta_open(mbfsp);
    if (ev(err))
        goto err_exit;

    *handle = mbfsp;

    return 0;

err_exit:
    while (i-- > 0)
        mblock_file_close(mbfsp->filev[i]);
    free(mbfsp);

    return err;
}

void
mblock_fset_close(struct mblock_fset *mbfsp)
{
    int i;

    if (ev(!mbfsp))
        return;

    i = mbfsp->filec;
    while (i-- > 0)
        mblock_file_close(mbfsp->filev[i]);

    mblock_fset_meta_close(mbfsp);

    free(mbfsp);
}

static int
mblock_fset_removecb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if (strstr(path, "mblock-data"))
        return remove(path);

    return 0;
}

void
mblock_fset_remove(struct mblock_fset *mbfsp)
{
    const char *dpath = mclass_dpath(mbfsp->mc);

    mblock_fset_close(mbfsp);

    nftw(dpath, mblock_fset_removecb, MBLOCK_FSET_FILES_DEFAULT, FTW_DEPTH | FTW_PHYS);

    mblock_fset_meta_remove(dpath);
}

merr_t
mblock_fset_alloc(struct mblock_fset *mbfsp, int mbidc, uint64_t *mbidv)
{
    struct mblock_file *mbfp;

    merr_t err;
    int fidx;
    int retries;

    if (ev(!mbfsp || !mbidv))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    retries = mbfsp->filec - 1;

    do {
        fidx = atomic64_fetch_add(1, &mbfsp->fidx) % mbfsp->filec;

        mbfp = mbfsp->filev[fidx];
        assert(mbfp);

        err = mblock_file_alloc(mbfp, mbidc, mbidv);
        if (merr_errno(err) != ENOSPC)
            break;
    } while (retries--);

    return err;
}

merr_t
mblock_fset_commit(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->filec))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_commit(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_abort(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->filec))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_abort(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_delete(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->filec))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_delete(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_find(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->filec))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_find(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_write(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp) || file_id(mbid) > mbfsp->filec)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_write(mbfp, mbid, iov, iovc, off);
}

merr_t
mblock_fset_read(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || file_id(mbid) > mbfsp->filec))
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_read(mbfp, mbid, iov, iovc, off);
}
