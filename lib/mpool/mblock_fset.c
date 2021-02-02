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
#include "mblock.h"

/* Init metadata file that persists mblocks in the data files */
static merr_t
mblock_fset_meta_open(struct mblock_fset *mfs)
{
    char name[32];
    int  fd;
    merr_t err;

    snprintf(name, sizeof(name), "%s", "mblock-meta");

    fd = openat(mclass_dirfd(mfs->mc), name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        hse_elog(HSE_ERR "open/create meta file failed, mclass dir %s: @@e",
                 err, mclass_dpath(mfs->mc));
    }

    mfs->meta_fd = fd;

    return 0;
}

static void
mblock_fset_meta_close(struct mblock_fset *mfs)
{
    close(mfs->meta_fd);
}

static void
mblock_fset_meta_remove(const char *dpath)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/%s", dpath, "mblock-meta");

    remove(path);
}

merr_t
mblock_fset_open(struct media_class *mc, struct mblock_fset **handle)
{
    struct mblock_fset *mfs;

    size_t sz;
    merr_t err;
    int    i;

    if (ev(!mc || !handle))
        return merr(EINVAL);

    sz = sizeof(*mfs) + MBLOCK_FS_FCNT_DFLT * sizeof(void *);

    mfs = calloc(1, sz);
    if (ev(!mfs))
        return merr(ENOMEM);

    mfs->mc = mc;
    mfs->filec = MBLOCK_FS_FCNT_DFLT;
    mfs->filev = (void *)(mfs + 1);

    for (i = 0; i < mfs->filec; i++) {
        char name[32];

        snprintf(name, sizeof(name), "%s-%d-%d", "mblock-data", mclass_id(mc), i);

        err = mblock_file_open(mfs, mclass_dirfd(mc), name, &mfs->filev[i]);
        if (ev(err))
            goto err_exit;
    }

    err = mblock_fset_meta_open(mfs);
    if (ev(err))
        goto err_exit;

    *handle = mfs;

    return 0;

err_exit:
    while (i-- > 0)
        mblock_file_close(mfs->filev[i]);
    free(mfs);

    return err;
}

void
mblock_fset_close(struct mblock_fset *mfs)
{
    int i;

    if (ev(!mfs))
        return;

    i = mfs->filec;
    while (i-- > 0)
        mblock_file_close(mfs->filev[i]);

    mblock_fset_meta_close(mfs);

    free(mfs);
}

static int
mblock_fset_removecb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if (strstr(path, "mblock-data"))
        return remove(path);

    return 0;
}

void
mblock_fset_remove(struct mblock_fset *mfs)
{
    const char *dpath = mclass_dpath(mfs->mc);

    mblock_fset_close(mfs);

    nftw(dpath, mblock_fset_removecb, MBLOCK_FS_FCNT_DFLT, FTW_DEPTH | FTW_PHYS);

    mblock_fset_meta_remove(dpath);
}
